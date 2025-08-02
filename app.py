from flask import Flask, render_template_string, request, redirect, url_for, flash
from netmiko import ConnectHandler

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flash messages

# Example firewall inventory (add your firewalls here)
FIREWALLS = {
    'FW1': {
        'device_type': 'fortinet',
        'host': '192.168.1.1',
        'username': 'admin',
        'password': 'password',
    },
    'FW2': {
        'device_type': 'fortinet',
        'host': '192.168.2.1',
        'username': 'admin',
        'password': 'password',
    },
}

HTML_FORM = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiGate Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
    <style>
        body { background: #f8fafc; }
        .dashboard-card { border-radius: 1rem; }
        .nav-tabs .nav-link.active { background: #0d6efd; color: #fff; }
        .nav-tabs .nav-link { color: #0d6efd; }
        .console-output { background: #222; color: #eee; padding: 1em; border-radius: 0.5em; font-family: monospace; }
    </style>
</head>
<body>
<div class="container py-5">
    <div class="row mb-4">
        <div class="col-12 text-center">
            <h1 class="fw-bold">FortiGate Firewall Dashboard</h1>
            <p class="lead">Policy Lookup &amp; Network Tools</p>
        </div>
    </div>
    <div class="card dashboard-card shadow-lg">
        <div class="card-body">
            <ul class="nav nav-tabs mb-3" id="dashboardTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="policy-tab" data-bs-toggle="tab" data-bs-target="#policy" type="button" role="tab">Policy Lookup</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="traceroute-tab" data-bs-toggle="tab" data-bs-target="#traceroute" type="button" role="tab">Traceroute Console</button>
                </li>
            </ul>
            <div class="tab-content" id="dashboardTabsContent">
                <div class="tab-pane fade show active" id="policy" role="tabpanel">
                    <form method="post" class="row g-3" action="/">
                        <div class="col-md-3">
                            <label for="firewall" class="form-label">Select Firewall</label>
                            <select name="firewall" id="firewall" class="form-select" required style="width:100%">
                                {% for fw in firewalls %}
                                <option value="{{ fw }}">{{ fw }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label for="src" class="form-label">Source IP</label>
                            <input type="text" name="src" id="src" class="form-control" required>
                        </div>
                        <div class="col-md-3">
                            <label for="dst" class="form-label">Destination IP</label>
                            <input type="text" name="dst" id="dst" class="form-control" required>
                        </div>
                        <div class="col-md-2">
                            <label for="port" class="form-label">Port</label>
                            <input type="text" name="port" id="port" class="form-control" required>
                        </div>
                        <div class="col-md-1 d-flex align-items-end">
                            <button type="submit" class="btn btn-primary w-100">Lookup</button>
                        </div>
                    </form>
                    {% if result %}
                    <div class="alert alert-info mt-4">
                        <h5>Policy Lookup Result:</h5>
                        <pre>{{ result }}</pre>
                    </div>
                    {% endif %}
                    {% with messages = get_flashed_messages() %}
                      {% if messages %}
                        <div class="alert alert-danger mt-4">
                          {% for message in messages %}
                            <div>{{ message }}</div>
                          {% endfor %}
                        </div>
                      {% endif %}
                    {% endwith %}
                </div>
                <div class="tab-pane fade" id="traceroute" role="tabpanel">
                    <form method="post" class="row g-3" action="/traceroute">
                        <div class="col-md-4">
                            <label for="tr_fw" class="form-label">Select Firewall</label>
                            <select name="firewall" id="tr_fw" class="form-select" required style="width:100%">
                                {% for fw in firewalls %}
                                <option value="{{ fw }}">{{ fw }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label for="tr_dst" class="form-label">Destination IP/Hostname</label>
                            <input type="text" name="dst" id="tr_dst" class="form-control" required>
                        </div>
                        <div class="col-md-2 d-flex align-items-end">
                            <button type="submit" class="btn btn-success w-100">Traceroute</button>
                        </div>
                    </form>
                    {% if traceroute_result %}
                    <div class="mt-4">
                        <h5>Traceroute Output:</h5>
                        <div class="console-output">{{ traceroute_result|safe }}</div>
                    </div>
                    {% endif %}
                    {% with messages = get_flashed_messages() %}
                      {% if messages %}
                        <div class="alert alert-danger mt-4">
                          {% for message in messages %}
                            <div>{{ message }}</div>
                          {% endfor %}
                        </div>
                      {% endif %}
                    {% endwith %}
                </div>
            </div>
        </div>
    </div>
</div>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#firewall').select2({
                placeholder: 'Select a firewall',
                allowClear: true
            });
            $('#tr_fw').select2({
                placeholder: 'Select a firewall',
                allowClear: true
            });
        });
    </script>
</body>
</html>
'''


def lookup_policy(fw_params, src, dst, port):
    try:
        net_connect = ConnectHandler(**fw_params)
        command = f"diagnose firewall policy lookup {src} {dst} {port}"
        output = net_connect.send_command(command)
        net_connect.disconnect()
        return output
    except Exception as e:
        return f"Error: {str(e)}"

def traceroute(fw_params, dst):
    try:
        net_connect = ConnectHandler(**fw_params)
        # FortiGate traceroute command
        command = f"execute traceroute {dst}"
        output = net_connect.send_command(command)
        net_connect.disconnect()
        # Attempt to highlight hostnames and hops
        lines = output.splitlines()
        formatted = []
        for line in lines:
            if line.strip().startswith('traceroute'):
                formatted.append(f'<b>{line}</b>')
            elif line.strip():
                # Try to extract hop number, hostname, and IP
                import re
                m = re.match(r"\s*(\d+)\s+([\w\.-]+)\s+\(([^)]+)\)", line)
                if m:
                    hop, host, ip = m.groups()
                    formatted.append(f'<span style="color:#0d6efd;font-weight:bold">{hop}</span> <span style="color:#20c997">{host}</span> <span style="color:#ffc107">({ip})</span>')
                else:
                    formatted.append(line)
        return '<br>'.join(formatted)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    traceroute_result = None
    if request.method == 'POST':
        firewall = request.form.get('firewall')
        src = request.form.get('src')
        dst = request.form.get('dst')
        port = request.form.get('port')
        fw_params = FIREWALLS.get(firewall)
        if not fw_params:
            flash('Invalid firewall selected.')
        else:
            result = lookup_policy(fw_params, src, dst, port)
    return render_template_string(HTML_FORM, firewalls=FIREWALLS.keys(), result=result, traceroute_result=traceroute_result)

@app.route('/traceroute', methods=['POST'])
def traceroute_console():
    result = None
    traceroute_result = None
    firewall = request.form.get('firewall')
    dst = request.form.get('dst')
    fw_params = FIREWALLS.get(firewall)
    if not fw_params:
        flash('Invalid firewall selected.')
    else:
        traceroute_result = traceroute(fw_params, dst)
    return render_template_string(HTML_FORM, firewalls=FIREWALLS.keys(), result=result, traceroute_result=traceroute_result)

if __name__ == '__main__':
    app.run(debug=True)
