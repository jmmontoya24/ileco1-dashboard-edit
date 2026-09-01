import eventlet
eventlet.monkey_patch()

from app import app, socketio

application = app

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)