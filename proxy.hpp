#ifndef __HTTPPROXY_PROXY__HPP__
#define __HTTPPROXY_PROXY__HPP__

#include <functional>
#include <map>
#include <vector>
#include <memory>
#include "stringutil.hpp"

/* TODO:
 * - Support CONNECT requests.
 */

class HttpProxy {
private:
	struct Impl;
	Impl* impl;

public:
	HttpProxy(const std::string& listenaddress, unsigned short listenport = 0);
	~HttpProxy();
	void run();
	bool poll();

	typedef std::map<std::string, std::vector<std::string>, StringUtil::case_insensitive_compare> Headers;

	struct Response {
		std::string response_version;
		std::string status_code;
		std::string status_message;
		std::string headers_raw;
		Headers headers;
		std::string body;
	// internal body transfer use only
		bool is_chunky;
		std::size_t remaining;
	};

	class Connection : public std::enable_shared_from_this<Connection> {
	private:
		struct Impl;
		Impl* impl;
		Connection(HttpProxy::Impl* parent);
		HttpProxy::Impl* parent;
		friend HttpProxy::Impl;

	public:
		~Connection();

		typedef std::shared_ptr<Connection> Ptr;

		std::string request_method;
		std::string request_url;
		std::string request_domain;
		std::string request_port;
		std::string request_path; //Path includes query parameters
		std::string request_headers_raw;
		Headers request_headers;
		std::string request_body;

		// Get what the remote response is to the request.
		void async_get_remote(Headers req_headers, std::function<void(Ptr, Response)> handler);
		// Get what the remote response is to the request, then immediately send it to the client.
		void forward() { forward(request_headers); }
		void forward(Headers req_headers);

		// Send an arbitrary reply to the client.
		void reply(std::string status_code, std::string status_message, Headers headers, std::string body);
	};

	void on_connection(std::function<void(Connection::Ptr)>);
	void on_failure(std::function<void(std::string message, bool is_critical)>);

	int get_local_port_number();
};

#endif