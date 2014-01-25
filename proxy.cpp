#include "proxy.hpp"

#define ASIO_STANDALONE
#include <asio.hpp>
#include <queue>

using namespace std::placeholders;

struct HttpProxy::Impl {
	Impl(const std::string& listenaddress, unsigned short listenport) 
		: io_service()
		, endpoint(asio::ip::address().from_string(listenaddress), listenport)
		, acceptor(io_service, endpoint)
	{
		acceptor.listen();
		do_accept();
	}
	asio::io_service io_service;
	asio::ip::tcp::endpoint endpoint;
	asio::ip::tcp::acceptor acceptor;
	std::function<void(Connection::Ptr)> on_connection;
	std::function<void(std::string, bool)> on_failure;

	void do_accept();
	void fail(std::string, bool);
};

struct HttpProxy::Connection::Impl {
	Impl(HttpProxy::Impl *parent)
		: clientsocket(parent->io_service)
		, serversocket(parent->io_service)
		, resolver(parent->io_service)
	{}
	asio::ip::tcp::socket clientsocket;
	asio::ip::tcp::socket serversocket;
	asio::ip::tcp::resolver resolver;
	asio::streambuf clientrecvbuf;
	asio::streambuf serverrecvbuf;
	std::string serversendbuf;
	std::queue<std::string> clientsendbuf;
	void start(Ptr cxn);
	void on_client_headers(Ptr cxn, const std::error_code& ec, size_t);
	void do_server_get(Ptr cxn, Headers req_headers, std::function<void(Ptr, Response)>);
	void on_server_resolve(Ptr cxn, std::function<void(Ptr, Response)> fn, asio::ip::tcp::resolver::iterator endpoint);
	void on_server_headers(Ptr cxn, std::function<void(Ptr, Response)>, const std::error_code& ec, size_t);
	void do_server_body(Ptr cxn, Response resp, std::function<void(std::string, bool)> fn);
	void tweak_headers(Headers& headers, bool ischunked, size_t bodysize = 0);
	void do_client_reply_headers(Ptr cxn, std::string status_code, std::string status_message, Headers headers);
	void do_client_write_raw(Ptr cxn, std::string);
	bool do_client_write_chunk(Ptr cxn, std::string);
	void do_client_write_sendbuf_handler(Ptr cxn);
};

///////////////////////////////////////////////////////////////////////////////////////////////////
// HttpProxy
///////////////////////////////////////////////////////////////////////////////////////////////////

HttpProxy::HttpProxy(const std::string& listenaddress, unsigned short listenport) {
	impl = new Impl(listenaddress, listenport);
}

HttpProxy::~HttpProxy() {
	delete impl;
}

void HttpProxy::run() {
	impl->io_service.run();
}

bool HttpProxy::poll() {
	return impl->io_service.poll() > 0;
}

void HttpProxy::on_connection(std::function<void(Connection::Ptr)> handler) {
	impl->on_connection = handler;
}

void HttpProxy::on_failure(std::function<void(std::string, bool)> handler) {
	impl->on_failure = handler;
}

int HttpProxy::get_local_port_number() {
	return impl->acceptor.local_endpoint().port();
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// HttpProxy::Impl
///////////////////////////////////////////////////////////////////////////////////////////////////

void HttpProxy::Impl::do_accept() {
	HttpProxy::Connection::Ptr cxn(new HttpProxy::Connection(this));
	acceptor.async_accept(cxn->impl->clientsocket, [this, cxn](const std::error_code& error){
		if (!error) {
			cxn->impl->start(cxn);
			do_accept();
		} else {
			fail("do_accept: " + error.message() + " (" + std::to_string(error.value()) + ")", true);
		}
	});
}

void HttpProxy::Impl::fail(std::string str, bool is_critical = false) {
	if (on_failure)
		on_failure(str, is_critical);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// HttpProxy::Connection
///////////////////////////////////////////////////////////////////////////////////////////////////

HttpProxy::Connection::Connection(HttpProxy::Impl* parent) {
	this->parent = parent;
	impl = new HttpProxy::Connection::Impl(parent);
}

HttpProxy::Connection::~Connection() {
	delete impl;
}

void HttpProxy::Connection::async_get_remote(Headers req_headers, std::function<void(Ptr, Response)> handler) {
	impl->do_server_get(this->shared_from_this(), req_headers, [handler](Ptr cxn, Response resp){
		resp.body.clear();
		auto accumulator = std::make_shared<std::string>();
		cxn->impl->do_server_body(cxn, resp, [cxn, resp, handler, accumulator](std::string str, bool error) mutable {
			if (error) return;
			if (str.empty()) {
				resp.body = *accumulator;
				handler(cxn, resp);
				return;
			}
			*accumulator += str;
		});
	});
}

void HttpProxy::Connection::forward(Headers req_headers) {
	impl->do_server_get(this->shared_from_this(), req_headers, [this](Ptr cxn, Response resp){
		impl->tweak_headers(resp.headers, true);
		impl->do_client_reply_headers(cxn, resp.status_code, resp.status_message, resp.headers);
		impl->do_server_body(cxn, resp, [cxn, this](std::string str, bool error) mutable {
			if (error) return;
			impl->do_client_write_chunk(cxn, str);
		});
	});
}

void HttpProxy::Connection::reply(std::string status_code, std::string status_message, Headers headers, std::string body) {
	impl->tweak_headers(headers, false, body.size());
	impl->do_client_reply_headers(this->shared_from_this(), status_code, status_message, headers);
	impl->do_client_write_raw(this->shared_from_this(), body);
}


///////////////////////////////////////////////////////////////////////////////////////////////////
// Misc Parsers
///////////////////////////////////////////////////////////////////////////////////////////////////

typedef asio::buffers_iterator<asio::streambuf::const_buffers_type> stream_buf_iterator;
// Match the regular expression: \n\r?\n
// Yes, some servers/clients do use only line feeds.
std::pair<stream_buf_iterator, bool> end_of_read_headers(stream_buf_iterator start, stream_buf_iterator end) {
	std::string str(start, end);

	auto i = str.find("\n\r\n");
	if (i != std::string::npos)
		return std::make_pair(start + i + 3, true);

	i = str.find("\n\n");
	if (i != std::string::npos)
		return std::make_pair(start + i + 2, true);

	i = str.find_last_of('\n');
	if (i != std::string::npos)
		return std::make_pair(start + i, false);

	return std::make_pair(end, false);
}

std::function<std::pair<stream_buf_iterator, bool>(stream_buf_iterator, stream_buf_iterator)> read_exactly(size_t bytes) {
	return [bytes](stream_buf_iterator start, stream_buf_iterator end) -> std::pair<stream_buf_iterator, bool> {
		assert(end - start >= 0);
		if ((size_t)(end - start) < bytes) {
			return std::make_pair(start, false);
		}
		return std::make_pair(start + bytes, true);
	};
}

std::function<std::pair<stream_buf_iterator, bool>(stream_buf_iterator, stream_buf_iterator)> read_at_most(size_t bytes) {
	return [bytes](stream_buf_iterator start, stream_buf_iterator end) -> std::pair<stream_buf_iterator, bool> {
		if (end == start) return std::make_pair(start, false);
		assert(end - start >= 0);
		if ((size_t)(end - start) < bytes) {
			return std::make_pair(end, true);
		}
		return std::make_pair(start + bytes, true);
	};
}

bool parse_url(HttpProxy::Connection::Ptr cxn) {
	std::string url = cxn->request_url;
	if (url.substr(0, 7) != "http://") {
		return false;
	}
	url.erase(0, 7);

	cxn->request_domain.clear();
	cxn->request_port = "80";
	cxn->request_path = "/";

	while (!url.empty() && url[0] != ':' && url[0] != '/') {
		cxn->request_domain += url[0];
		url.erase(0, 1);
	}

	if (!url.empty()) {
		if (url[0] == ':') {
			url.erase(0, 1);
			cxn->request_port.clear();
			while (!url.empty() && url[0] != '/') {
				cxn->request_port += url[0];
				url.erase(0, 1);
			}
		}
	}

	if (!url.empty()) {
		cxn->request_path = url;
	}

	return true;
}

// Real life is always slightly more complex than one normally thinks.
bool parse_headers(std::string str, HttpProxy::Headers& headers) {
	headers.clear();
	while (!str.empty()) {
		auto i = str.find(':');
		if (i == std::string::npos) return false;
		std::string header_name = StringUtil::trim(str.substr(0, i));
		str.erase(0, i+1);
		
		i = str.find('\n');
		if (i == std::string::npos) return false;
		std::string header_value = str.substr(0, i+1);
		str.erase(0, i+1);
		while (!str.empty()) { // MULTI-LINE HEADER SUPPORT HO
			if (!::isspace(str[0])) break;
			i = str.find('\n');
			if (i == std::string::npos) return false;
			header_value += str.substr(0, i+1);
			str.erase(0, i+1);
		}

		headers[header_name].emplace_back(StringUtil::trim(header_value));
	}
	return true;
}

bool header_contains(const HttpProxy::Headers& headers, const std::string& h){
	auto header = headers.find(h);
	if (header == headers.end()) return false;
	return true;
}

bool header_contains(const HttpProxy::Headers& headers, const std::string& h, std::string val){
	auto header = headers.find(h);
	if (header == headers.end()) return false;

	val = StringUtil::upper(val);
	for (auto& v : header->second) {
		if (StringUtil::upper(v).find(val) != std::string::npos) return true;
	}

	return false;
}

// Read the contents of a streambuf
std::string read_str_from_buf(asio::streambuf& buf, size_t size) {
	auto dataiter = asio::buffers_begin(buf.data());
	assert(buf.size() >= size);
	std::string recvdata(dataiter, dataiter + size);
	buf.consume(size);
	return recvdata;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Chunked Encoding Parser
///////////////////////////////////////////////////////////////////////////////////////////////////

void do_chunked_encoding_head(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out, std::string in);
void do_chunked_encoding_body(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out, std::string in, size_t len);
void do_chunked_encoding_term(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out, std::string in);

void do_chunked_encoding(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out) {
	get_more(std::bind(&do_chunked_encoding_head, get_more, done, out, _1));
}

void do_chunked_encoding_head(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out, std::string in) {
	size_t body_size = std::stoll(in, 0, 0x10);
	if (body_size == 0) {
		get_more(std::bind(&do_chunked_encoding_term, get_more, done, out, _1));
	} else {
		get_more(std::bind(&do_chunked_encoding_body, get_more, done, out, _1, body_size));
	}
}

void do_chunked_encoding_body(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out, std::string in, size_t len) {
	if (in.length() > len + 2) {
		done(false);
		return;
	}

	if (in.length() == len + 2) {
		out(std::string(in.begin(), in.end()-2));
		get_more(std::bind(&do_chunked_encoding_head, get_more, done, out, _1));
	} else { //embedded /r/n
		len -= in.length();
		out(in);
		get_more(std::bind(&do_chunked_encoding_body, get_more, done, out, _1, len));
	}
}

void do_chunked_encoding_term(std::function<void(std::function<void(std::string)>)> get_more, std::function<void(bool)> done, std::function<void(const std::string&)> out, std::string in) {
	if (in.length() == 2) {
		done(true);
	} else {
		get_more(std::bind(&do_chunked_encoding_term, get_more, done, out, _1));
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// HttpProxy::Connection::Impl
///////////////////////////////////////////////////////////////////////////////////////////////////

void HttpProxy::Connection::Impl::start(Ptr cxn) {
	asio::async_read_until(clientsocket, clientrecvbuf, &end_of_read_headers, std::bind(&Impl::on_client_headers, this, cxn, _1, _2));
}

void HttpProxy::Connection::Impl::on_client_headers(Ptr cxn, const std::error_code& error, size_t recvsiz) {
	if (error) {
		cxn->parent->fail("on_client_headers: " + error.message() + " (" + std::to_string(error.value()) + ")");
		return;
	}

	std::string recvdata = read_str_from_buf(clientrecvbuf, recvsiz);

	auto i = recvdata.find("\n");
	std::string request_line = StringUtil::rtrim(recvdata.substr(0, i));
	cxn->request_headers_raw = recvdata.substr(i+1);

	i = request_line.find(' ');
	if (i == std::string::npos) {
		cxn->parent->fail("on_client_headers: malformed first line");
		return;
	}
	cxn->request_method = request_line.substr(0, i);
	request_line.erase(0, i+1);

	i = request_line.find(' ');
	if (i == std::string::npos) {
		cxn->parent->fail("on_client_headers: malformed first line");
		return;
	}
	cxn->request_url = request_line.substr(0, i);
	request_line.erase(0, i+1);

	std::string request_version = StringUtil::upper(request_line);
	if (request_version != "HTTP/1.1") {
		cxn->parent->fail("on_client_headers: malformed first line");
		return;
	}

	if (!parse_url(cxn)) {
		cxn->parent->fail("on_client_headers: expected http:// in cxn->request_url");
		return;
	}

	if (!parse_headers(cxn->request_headers_raw, cxn->request_headers)) {
		cxn->parent->fail("on_client_headers: malformed headers: " + cxn->request_headers_raw);
		return;
	}

	cxn->request_body.clear();
	if (header_contains(cxn->request_headers, "Transfer-Encoding", "chunked")) {
		// Yes, some clients send chunked bodies.
		//printf("GOT A CHUNKY CLIENT, SEND HELP\n");
		do_chunked_encoding([cxn, this](std::function<void(std::string)> fn){
			asio::async_read_until(clientsocket, clientrecvbuf, "\r\n", [cxn, this, fn](const std::error_code& error, size_t recvsiz){
				if (error) {
					cxn->parent->fail("do_client_chunky_body: " + error.message() + " (" + std::to_string(error.value()) + ")");
					return;
				}
				fn(read_str_from_buf(clientrecvbuf, recvsiz)); 
			});
		}, [cxn](bool no_error) {
			if (!no_error) {
				cxn->parent->fail("on_client_chunky_body: malformed chunkiness");
			} else {
				cxn->request_headers["Transfer-Encoding"].clear();
				cxn->request_headers["Content-Length"].clear();
				cxn->request_headers["Content-Length"].emplace_back(std::to_string(cxn->request_body.size()));
				cxn->parent->on_connection(cxn);
			}
		}, [cxn](const std::string& cat){
			cxn->request_body += cat;
		});
	} else if (header_contains(cxn->request_headers, "Content-Length")) {
		size_t length = std::stoll(cxn->request_headers["Content-Length"].front());
		asio::async_read_until(clientsocket, clientrecvbuf, read_exactly(length), [length, cxn, this](const std::error_code& error, size_t len){
			if (error) {
				cxn->parent->fail("do_client_body: " + error.message() + " (" + std::to_string(error.value()) + ")" + " bfusize: " + std::to_string(clientrecvbuf.size()) + "/" + std::to_string(len));
				return;
			} else if (len != length) {
				cxn->parent->fail("do_client_body: size fail (len: " + std::to_string(len) + ", expected: " + std::to_string(length) + ")");
				return;
			}

			cxn->request_body = read_str_from_buf(clientrecvbuf, len);

			cxn->parent->on_connection(cxn);
		});
	} else {
		cxn->parent->on_connection(cxn);
	}
}

void HttpProxy::Connection::Impl::do_server_get(Ptr cxn, Headers req_headers, std::function<void(Ptr, Response)> fn){
	serversendbuf.clear();
	serversendbuf = cxn->request_method + " " + cxn->request_path + " HTTP/1.1\r\n";
	for (const auto& header : req_headers) {
		for (const auto& v : header.second) {
			serversendbuf += header.first + ": " + v + "\r\n";
		}
	}
	serversendbuf += "\r\n";
	serversendbuf += cxn->request_body;

	resolver.async_resolve({cxn->request_domain, cxn->request_port}, [cxn, this, fn](const std::error_code& error, asio::ip::tcp::resolver::iterator endpoint_iterator){
		if (error) {
			cxn->parent->fail("do_server_get: Resolution of " + cxn->request_domain  + ":" + cxn->request_port + " failed.");
			return;
		}

		on_server_resolve(cxn, fn, endpoint_iterator);
	});
}

void HttpProxy::Connection::Impl::on_server_resolve(Ptr cxn, std::function<void(Ptr, Response)> fn, asio::ip::tcp::resolver::iterator endpoint) {
	asio::async_connect(serversocket, endpoint, [cxn, this, fn](const std::error_code& error, asio::ip::tcp::resolver::iterator iterator){
		if (error) {
			if (iterator != asio::ip::tcp::resolver::iterator()) {
				on_server_resolve(cxn, fn, ++iterator);
				return;
			}
			cxn->parent->fail("do_server_get: Could not connect to " + cxn->request_domain  + ":" + cxn->request_port + ".");
			return;
		}

		asio::async_write(serversocket, asio::buffer(serversendbuf), [cxn, this, fn](const std::error_code&, size_t){
			asio::async_read_until(serversocket, serverrecvbuf, &end_of_read_headers, std::bind(&Impl::on_server_headers, this, cxn, fn, _1, _2));
		});
	});
}

void HttpProxy::Connection::Impl::on_server_headers(Ptr cxn, std::function<void(Ptr, Response)> fn, const std::error_code& error, size_t recvsiz) {
	if (error) {
		cxn->parent->fail("on_server_headers: " + error.message() + " (" + std::to_string(error.value()) + ")");
		return;
	}

	std::string recvdata = read_str_from_buf(serverrecvbuf, recvsiz);

	Response ret;

	auto i = recvdata.find("\n");
	std::string response_line = StringUtil::rtrim(recvdata.substr(0, i));
	ret.headers_raw = recvdata.substr(i+1);

	i = response_line.find(' ');
	if (i == std::string::npos) {
		cxn->parent->fail("on_server_headers: malformed first line");
		return;
	} else if (response_line.substr(0, i) != "HTTP/1.1") {
		cxn->parent->fail("on_server_headers: unknown HTTP version");
		return;
	}
	response_line.erase(0, i+1);

	i = response_line.find(' ');
	if (i == std::string::npos) {
		cxn->parent->fail("on_server_headers: malformed first line");
		return;
	}
	ret.status_code = response_line.substr(0, i);
	response_line.erase(0, i+1);

	ret.status_message = response_line;

	if (!parse_headers(ret.headers_raw, ret.headers)) {
		cxn->parent->fail("on_server_headers: malformed headers: " + cxn->request_headers_raw);
		return;
	}

	ret.body.clear();
	ret.is_chunky = false;
	if (header_contains(ret.headers, "Transfer-Encoding", "chunked")) {
		//printf("GOT A CHUNKY SERVER, SEND HELP\n");
		ret.is_chunky = true;
	} else if (header_contains(ret.headers, "Content-Length")) {
		long long length = std::stoll(ret.headers["Content-Length"].front());
		ret.remaining = length;
	} else {
		ret.remaining = 0;
	}

	fn(cxn, ret);
}

void HttpProxy::Connection::Impl::do_server_body(Ptr cxn, Response resp, std::function<void(std::string, bool)> fn) {
	if (resp.is_chunky) {
		do_chunked_encoding([cxn, this](std::function<void(std::string)> fn){
			asio::async_read_until(serversocket, serverrecvbuf, "\r\n", [cxn, this, fn](const std::error_code& error, size_t recvsiz){
				if (error) {
					cxn->parent->fail("do_server_chunky_body: " + error.message() + " (" + std::to_string(error.value()) + ")");
					return;
				}
				fn(read_str_from_buf(serverrecvbuf, recvsiz)); 
			});
		}, [cxn, fn](bool no_error) {
			if (!no_error) {
				cxn->parent->fail("do_server_chunky_body: malformed chunkiness");
			} else {
				fn("", false);
			}
		}, [cxn, fn](const std::string& cat){
			if (!cat.empty()) fn(cat, false);
		});
		return;
	}

	if (resp.remaining == 0) {
		fn("", false);
		return;
	}

	asio::async_read_until(serversocket, serverrecvbuf, read_at_most(resp.remaining), [cxn, this, resp, fn](const std::error_code& error, size_t len) mutable {
		if (error) {
			cxn->parent->fail("do_server_body: " + error.message() + " (" + std::to_string(error.value()) + ")");
			return;
		}

		resp.remaining -= len;
		fn(read_str_from_buf(serverrecvbuf, len), false);
		do_server_body(cxn, resp, fn);
	});
}

void HttpProxy::Connection::Impl::tweak_headers(Headers& headers, bool ischunked, size_t bodysize){
	headers["Connection"].clear();
	headers["Connection"].emplace_back("close");

	headers["Transfer-Encoding"].clear();
	headers["Content-Length"].clear();
	if (ischunked) {
		headers["Transfer-Encoding"].emplace_back("chunked");
	} else if (bodysize != 0) {
		headers["Content-Length"].emplace_back(std::to_string(bodysize));
	}
}

void HttpProxy::Connection::Impl::do_client_reply_headers(Ptr cxn, std::string status_code, std::string status_message, Headers headers) {
	std::string buf;
	buf = "HTTP/1.1 " + status_code + " " + status_message + "\r\n";
	for (const auto& header : headers) {
		for (const auto& v : header.second) {
			buf += header.first + ": " + v + "\r\n";
		}
	}
	buf += "\r\n";
	do_client_write_raw(cxn, buf);
}

void HttpProxy::Connection::Impl::do_client_write_raw(Ptr cxn, std::string str) {
	bool isRunning = !clientsendbuf.empty();

	clientsendbuf.push(str);

	if (!isRunning) {
		do_client_write_sendbuf_handler(cxn);
	}
}

void HttpProxy::Connection::Impl::do_client_write_sendbuf_handler(Ptr cxn) {
	asio::async_write(this->clientsocket, asio::buffer(clientsendbuf.front()), [cxn, this](const std::error_code& error, std::size_t){
		if (error) {
			cxn->parent->fail("do_client_write_raw: " + error.message() + " (" + std::to_string(error.value()) + ")");
			return;
		}
		this->clientsendbuf.pop();
		if (!this->clientsendbuf.empty()) {
			do_client_write_sendbuf_handler(cxn);
		}
	});
}

bool HttpProxy::Connection::Impl::do_client_write_chunk(Ptr cxn, std::string str) {
	std::string tmp;
	tmp.resize(30);
	int n = std::sprintf((char*)tmp.c_str(), "%lX", str.size());
	tmp.resize(n);
	//cxn->parent->fail("writing chunk:\n" + tmp);
	do_client_write_raw(cxn, tmp + "\r\n" + str + "\r\n");
	return (str.size() == 0);
}
