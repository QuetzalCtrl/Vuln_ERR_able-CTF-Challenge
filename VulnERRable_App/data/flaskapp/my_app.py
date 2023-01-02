from flask import Flask, request, render_template_string, Response, abort, render_template

app = Flask(__name__, static_folder='static')
app.secret_key = b'SECRET_KEY'

def ip_allowed():
        if 'X-Forwarded-For' in request.headers:
           proxy_data = request.headers['X-Forwarded-For']
           ip_list = proxy_data.split(',')
           ip = ip_list[0]  # first address in list is User IP
        else:
           ip = request.remote_addr  # For local development
        return ip == "127.0.0.1"

@app.route('/2e51aab2-8824-47a6-9492-2dd9d533644a', methods=['GET'])
def vulndir():
        if not ip_allowed():
           abort(403, description="Only 127.0.0.1 can access this page")
        command = request.args.get('command')
        esc_chars = "'_#&;[]"
        
        if command is None:
          command = 'Q2hlY2sgZm9yIGFueSBHRVQgcGFyYW1z'
        else:
          if any(char in esc_chars for char in command):
            command = "Invalid command, please make sure it doesn't contain any of these characters: '_#&;[]"

        template = '''<!DOCTYPE html>
        <html>
          <head>
            <title>Secret Page</title>
          </head>
          <body>
            <p>''' + command + '''</p>
          </body>
        </html>'''

        return render_template_string(template)

@app.route("/")
def hello_world():
    return render_template('index.html')

@app.route('/robots.txt')
def noindex():
    r = Response(response="User-agent: *\nDisallow: /2e51aab2-8824-47a6-9492-2dd9d533644a\n", status=200, mimetype="text/plain")
    r.headers["Content-Type"] = "text/plain; charset=utf-8"
    return r

#if __name__ == '__main__':
#        app.run(host='127.0.0.1', port=8080, debug=False)                                                                                                                                                            "ubuntu1" 01:53 02-janv.-23

