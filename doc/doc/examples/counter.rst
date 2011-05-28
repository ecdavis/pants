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
        
        request.send_status(200)
        request.send_headers({
            'Content-Length': len(str(count)),
            'Content-Type': 'text/plain'
            })
        
        request.write(str(count))
        request.finish()
    
    HTTPServer(request_handler).listen()
    engine.start()
