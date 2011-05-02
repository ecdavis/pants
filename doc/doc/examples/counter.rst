Counter
*******

A simple HTTP server that returns (as plain text) the number of times the page
has been requested::

    from pants.contrib.http import HTTPServer
    from pants import engine
    
    count = 0
    
    def request_handler(request):
        global count
        
        count += 1
        
        request.write(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: %d\r\n" % len(str(count))
            "\r\n"
            str(count)
            )
        request.finish()
    
    HTTPServer(request_handler).listen()
    engine.start()
