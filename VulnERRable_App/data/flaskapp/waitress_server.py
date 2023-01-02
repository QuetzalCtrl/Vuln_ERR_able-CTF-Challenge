from waitress import serve
import my_app
serve(my_app.app, host='127.0.0.1', port=8080)