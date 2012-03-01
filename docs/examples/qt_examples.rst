Qt
**


Using ``pants.contrib.qt``
==========================

.. code-block:: python

    # First, create a simple web application with Pants.
    from pants.web import Application, HTTPServer

    webapp = Application()
    @webapp.route("/")
    def hello():
        return "Hello, World!"

    HTTPServer(webapp).listen(80)

    # Now, create a simple Qt application with a progress bar.
    from PySide.QtGui import QApplication, QProgressBar
    from PySide.QtCore import QTimer

    app = QApplication([])

    qb = QProgressBar()

    def update():
        value = qb.value() + 1
        if value > qb.maximum():
            value = qb.minimum()
        qb.setValue(value)

    tmr = QTimer(qb)
    tmr.timeout.connect(update)

    tmr.start(100)
    qb.show()

    # Install the Qt poller for Pants.
    from pants.contrib.qt import install
    install(app)

    # Now, run it.
    app.exec_()
