#include "proxy.hpp"
#include <iostream>

int main(int, char**)
{
	HttpProxy p("127.0.0.1", 8000);

	p.on_connection([](HttpProxy::Connection::Ptr cxn){
		std::cout << "Got a connection:" << std::endl;
		std::cout << "Method: " << cxn->request_method << std::endl;
		std::cout << "Path: " << cxn->request_path << std::endl;
		for (const auto& h : cxn->request_headers) {
			for (const auto& v : h.second) {
				std::cout << "Header: " << h.first << ": "<< v << std::endl;
			}
		}
		std::cout << "Raw Body: " << std::endl << cxn->request_body << std::endl;

		if (true) {
			cxn->request_headers["Accept-Encoding"].clear();
			cxn->request_headers["Accept-Encoding"].push_back("identity");
			cxn->async_get_remote(cxn->request_headers, [](HttpProxy::Connection::Ptr cxn, HttpProxy::Response resp){
				std::cout << "Request: " << cxn->request_domain << cxn->request_path << std::endl;
				std::cout << "Response Body: " << std::endl << resp.body << std::endl;
				cxn->reply(resp.status_code, resp.status_message, resp.headers, resp.body);
			});
		} else if (false) {
			cxn->forward();	
		} else {
			cxn->reply("200", "OK", HttpProxy::Headers(), "Requested: " + cxn->request_path);
		}
	});

	p.on_failure([](std::string str, bool){
		std::cout << str << std::endl;
	});

	p.run();
}
