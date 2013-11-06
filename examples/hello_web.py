from pants.web import Application

app = Application()

@app.route('/')
def hello(request):
    return "Hello, World!"

app.run()
