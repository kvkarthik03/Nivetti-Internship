from flask import Flask, send_from_directory, render_template, abort
import os

app = Flask(__name__)
Files_Folder = 'files'

@app.route('/')
def list_files():
    files = os.listdir(Files_Folder)
    return render_template('index.html', files=files)

@app.route('/download/<filename>', methods = ['GET'])
def download_file(filename):
    try:
        return send_from_directory(Files_Folder, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)
    
if(__name__ == '__main__'):
    app.run(host="10.0.2.15",port=5000, debug=True)