# backend/app.py
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room
from models import db, User, Role, ActivityLog
from proxmox_api import ProxmoxAPI
from datetime import timedelta
import os
from flasgger import Swagger, swag_from

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Update origins as needed

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///proxmox_manager.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your_email@example.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your_email_password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'your_email@example.com')

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # Update as needed
swagger = Swagger(app)

# Initialize ProxmoxAPI instances
PROXMOX_CONF = [
    {
        'host': 'proxmox1.example.com',
        'user': 'root@pam',
        'password': 'password1',
        'verify_ssl': False
    },
    {
        'host': 'proxmox2.example.com',
        'user': 'root@pam',
        'password': 'password2',
        'verify_ssl': False
    }
]

prox_instances = {}
for conf in PROXMOX_CONF:
    try:
        prox = ProxmoxAPI(
            host=conf['host'],
            user=conf['user'],
            password=conf['password'],
            verify_ssl=conf['verify_ssl']
        )
        prox_instances[conf['host']] = prox
    except Exception as e:
        print(f"Error initializing ProxmoxAPI for {conf['host']}: {e}")

# Create default roles and admin user if not exists
@app.before_first_request
def setup_defaults():
    db.create_all()
    if not Role.query.filter_by(name='admin').first():
        admin_role = Role(name='admin')
        db.session.add(admin_role)
        db.session.commit()
    if not Role.query.filter_by(name='read-only').first():
        read_only_role = Role(name='read-only')
        db.session.add(read_only_role)
        db.session.commit()
    if not User.query.filter_by(username='admin').first():
        hashed_pw = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
        admin_user = User(username='admin', password=hashed_pw)
        admin_role = Role.query.filter_by(name='admin').first()
        admin_user.roles.append(admin_role)
        db.session.add(admin_user)
        db.session.commit()

# Utility function to log activities
def log_activity(user_id, action, details=""):
    activity = ActivityLog(user_id=user_id, action=action, details=details)
    db.session.add(activity)
    db.session.commit()

# Utility function to send email notifications
def send_email(subject, recipients, body):
    msg = Message(subject, recipients=recipients, body=body)
    mail.send(msg)

# SocketIO event handler for real-time notifications
@socketio.on('connect')
@jwt_required()
def handle_connect():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        room = f"user_{user.id}"
        join_room(room)
        emit('message', {'msg': f'User {user.username} connected'}, room=room)

# Authentication Routes

@app.route('/api/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Login successful',
            'schema': {
                'properties': {
                    'access_token': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Invalid credentials'
        }
    }
})
def login():
    """
    User Login
    ---
    """
    data = request.json
    username = data.get('username', None)
    password = data.get('password', None)
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=user.id)
    log_activity(user.id, "Logged in")
    return jsonify(access_token=access_token), 200

@app.route('/api/register', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    'roles': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                },
                'required': ['username', 'password', 'roles']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'User created successfully'
        },
        400: {
            'description': 'User already exists or invalid roles'
        },
        403: {
            'description': 'Unauthorized'
        }
    }
})
def register():
    """
    Register New User (Admin Only)
    ---
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user or not user.has_role('admin'):
        return jsonify({"msg": "Unauthorized"}), 403
    data = request.json
    username = data.get('username', None)
    password = data.get('password', None)
    roles = data.get('roles', [])
    if not username or not password or not roles:
        return jsonify({"msg": "Username, password, and roles are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 400
    user_roles = []
    for role_name in roles:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"msg": f"Role {role_name} does not exist"}), 400
        user_roles.append(role)
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_pw)
    new_user.roles.extend(user_roles)
    db.session.add(new_user)
    db.session.commit()
    log_activity(current_user_id, f"Registered new user: {username}", f"Roles: {', '.join(roles)}")
    return jsonify({"msg": "User created"}), 201

# Decorator for role-based access
from functools import wraps

def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                return jsonify({"msg": "User not found"}), 404
            user_roles = [role.name for role in user.roles]
            if not any(role in user_roles for role in roles):
                return jsonify({"msg": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# VM Management Routes

@app.route('/api/vms', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['VM Management'],
    'responses': {
        200: {
            'description': 'List of all VMs',
            'schema': {
                'type': 'array',
                'items': {
                    'properties': {
                        'vmid': {'type': 'integer'},
                        'name': {'type': 'string'},
                        'status': {'type': 'string'},
                        'datacenter': {'type': 'string'},
                        'node': {'type': 'string'}
                    }
                }
            }
        },
        401: {
            'description': 'Unauthorized'
        }
    }
})
def get_all_vms():
    """
    Get All VMs
    ---
    """
    user_id = get_jwt_identity()
    try:
        all_vms = []
        for host, prox in prox_instances.items():
            vms = prox.get_vms()
            for vm in vms:
                vm['datacenter'] = host
                all_vms.append(vm)
        log_activity(user_id, "Fetched all VMs")
        return jsonify(all_vms), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vm/start', methods=['POST'])
@roles_required('admin')
@swag_from({
    'tags': ['VM Management'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'properties': {
                    'datacenter': {'type': 'string'},
                    'node': {'type': 'string'},
                    'vmid': {'type': 'integer'}
                },
                'required': ['datacenter', 'node', 'vmid']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'VM started successfully'
        },
        404: {
            'description': 'Datacenter not found'
        },
        500: {
            'description': 'Internal server error'
        }
    }
})
def start_vm():
    """
    Start a VM
    ---
    """
    user_id = get_jwt_identity()
    data = request.json
    host = data.get('datacenter')
    node = data.get('node')
    vmid = data.get('vmid')
    if host not in prox_instances:
        return jsonify({'error': 'Datacenter not found'}), 404
    try:
        result = prox_instances[host].start_vm(node, vmid)
        log_activity(user_id, f"Started VM {vmid} on {host}/{node}")
        # Emit real-time update
        socketio.emit('vm_update', {'action': 'start', 'vmid': vmid, 'host': host, 'node': node})
        return jsonify(result), 200
    except Exception as e:
        log_activity(user_id, f"Failed to start VM {vmid} on {host}/{node}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vm/stop', methods=['POST'])
@roles_required('admin')
@swag_from({
    'tags': ['VM Management'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'properties': {
                    'datacenter': {'type': 'string'},
                    'node': {'type': 'string'},
                    'vmid': {'type': 'integer'}
                },
                'required': ['datacenter', 'node', 'vmid']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'VM stopped successfully'
        },
        404: {
            'description': 'Datacenter not found'
        },
        500: {
            'description': 'Internal server error'
        }
    }
})
def stop_vm():
    """
    Stop a VM
    ---
    """
    user_id = get_jwt_identity()
    data = request.json
    host = data.get('datacenter')
    node = data.get('node')
    vmid = data.get('vmid')
    if host not in prox_instances:
        return jsonify({'error': 'Datacenter not found'}), 404
    try:
        result = prox_instances[host].stop_vm(node, vmid)
        log_activity(user_id, f"Stopped VM {vmid} on {host}/{node}")
        socketio.emit('vm_update', {'action': 'stop', 'vmid': vmid, 'host': host, 'node': node})
        return jsonify(result), 200
    except Exception as e:
        log_activity(user_id, f"Failed to stop VM {vmid} on {host}/{node}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vm/reboot', methods=['POST'])
@roles_required('admin')
@swag_from({
    'tags': ['VM Management'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'properties': {
                    'datacenter': {'type': 'string'},
                    'node': {'type': 'string'},
                    'vmid': {'type': 'integer'}
                },
                'required': ['datacenter', 'node', 'vmid']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'VM rebooted successfully'
        },
        404: {
            'description': 'Datacenter not found'
        },
        500: {
            'description': 'Internal server error'
        }
    }
})
def reboot_vm():
    """
    Reboot a VM
    ---
    """
    user_id = get_jwt_identity()
    data = request.json
    host = data.get('datacenter')
    node = data.get('node')
    vmid = data.get('vmid')
    if host not in prox_instances:
        return jsonify({'error': 'Datacenter not found'}), 404
    try:
        result = prox_instances[host].reboot_vm(node, vmid)
        log_activity(user_id, f"Rebooted VM {vmid} on {host}/{node}")
        socketio.emit('vm_update', {'action': 'reboot', 'vmid': vmid, 'host': host, 'node': node})
        return jsonify(result), 200
    except Exception as e:
        log_activity(user_id, f"Failed to reboot VM {vmid} on {host}/{node}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vm/migrate', methods=['POST'])
@roles_required('admin')
@swag_from({
    'tags': ['VM Management'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'properties': {
                    'source_datacenter': {'type': 'string'},
                    'target_datacenter': {'type': 'string'},
                    'node': {'type': 'string'},
                    'vmid': {'type': 'integer'}
                },
                'required': ['source_datacenter', 'target_datacenter', 'node', 'vmid']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'VM migrated successfully'
        },
        404: {
            'description': 'Datacenter not found'
        },
        500: {
            'description': 'Internal server error'
        }
    }
})
def migrate_vm():
    """
    Migrate a VM
    ---
    """
    user_id = get_jwt_identity()
    data = request.json
    source_host = data.get('source_datacenter')
    target_host = data.get('target_datacenter')
    node = data.get('node')
    vmid = data.get('vmid')
    if source_host not in prox_instances or target_host not in prox_instances:
        return jsonify({'error': 'Datacenter not found'}), 404
    try:
        result = prox_instances[source_host].migrate_vm(node, vmid, target_host)
        log_activity(user_id, f"Migrated VM {vmid} from {source_host}/{node} to {target_host}")
        # Send notification email
        user = User.query.get(user_id)
        if user:
            send_email(
                subject="VM Migration Successful",
                recipients=[user.username],  # Assuming username is email
                body=f"VM {vmid} has been successfully migrated from {source_host}/{node} to {target_host}."
            )
        # Emit real-time update
        socketio.emit('vm_update', {'action': 'migrate', 'vmid': vmid, 'source_host': source_host, 'target_host': target_host, 'node': node})
        return jsonify(result), 200
    except Exception as e:
        log_activity(user_id, f"Failed to migrate VM {vmid} from {source_host}/{node} to {target_host}: {str(e)}")
        # Send notification email about failure
        user = User.query.get(user_id)
        if user:
            send_email(
                subject="VM Migration Failed",
                recipients=[user.username],
                body=f"VM {vmid} migration from {source_host}/{node} to {target_host} failed.\nError: {str(e)}"
            )
        return jsonify({'error': str(e)}), 500

# Activity Logs Route
@app.route('/api/activity-logs', methods=['GET'])
@roles_required('admin')
@swag_from({
    'tags': ['Activity Logs'],
    'responses': {
        200: {
            'description': 'List of activity logs',
            'schema': {
                'type': 'array',
                'items': {
                    'properties': {
                        'id': {'type': 'integer'},
                        'username': {'type': 'string'},
                        'action': {'type': 'string'},
                        'timestamp': {'type': 'string'},
                        'details': {'type': 'string'}
                    }
                }
            }
        },
        403: {
            'description': 'Unauthorized'
        }
    }
})
def get_activity_logs():
    """
    Get Activity Logs (Admin Only)
    ---
    """
    try:
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
        log_list = []
        for log in logs:
            log_list.append({
                'id': log.id,
                'username': log.user.username if log.user else 'System',
                'action': log.action,
                'timestamp': log.timestamp.isoformat(),
                'details': log.details
            })
        return jsonify(log_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Load Balancing (Scheduler)
from apscheduler.schedulers.background import BackgroundScheduler

CPU_THRESHOLD = 80.0  # Percent
MEMORY_THRESHOLD = 80.0  # Percent

def get_vm_usage(prox, vm):
    try:
        stats = prox.get_vm_stats(vm['node'], vm['vmid'])
        return stats['cpu'], stats['memory']
    except Exception as e:
        return 0, 0  # In case of failure

def load_balance():
    print("Starting load balancing check...")
    try:
        node_resources = {}
        for host, prox in prox_instances.items():
            nodes = prox.get_nodes()
            for node in nodes:
                resources = prox.get_node_resources(node)
                cpu_usage = (resources['cpu'] / resources['maxcpu']) * 100
                mem_usage = (resources['memory'] / resources['maxmemory']) * 100
                node_resources[node] = {
                    'host': host,
                    'cpu': cpu_usage,
                    'memory': mem_usage
                }

        overloaded_nodes = [node for node, res in node_resources.items()
                            if res['cpu'] > CPU_THRESHOLD or res['memory'] > MEMORY_THRESHOLD]

        for node in overloaded_nodes:
            res = node_resources[node]
            print(f"Node {node} on {res['host']} is overloaded: CPU {res['cpu']}%, Memory {res['memory']}%")
            prox = prox_instances[res['host']]
            vms = prox.get_vms()
            node_vms = [vm for vm in vms if vm['node'] == node]
            if not node_vms:
                continue

            # Sort VMs by CPU usage ascending
            vms_sorted = sorted(node_vms, key=lambda vm: get_vm_usage(prox, vm)[0])

            for vm in vms_sorted:
                vm_cpu, vm_mem = get_vm_usage(prox, vm)
                if vm_cpu < CPU_THRESHOLD and vm_mem < MEMORY_THRESHOLD:
                    # Find target node
                    target_node = find_least_loaded_node(node_resources, exclude=node, host=res['host'])
                    if target_node:
                        try:
                            prox.migrate_vm(node, vm['vmid'], target_node)
                            log_activity(None, f"Automated migration of VM {vm['vmid']} from {node} to {target_node}")
                            # Emit real-time update
                            socketio.emit('vm_update', {'action': 'migrate', 'vmid': vm['vmid'], 
                                                       'source_host': res['host'], 'target_host': prox_instances[target_node].host, 
                                                       'node': node})
                            # Send notification to admins
                            admins = User.query.join(User.roles).filter(Role.name == 'admin').all()
                            admin_emails = [admin.username for admin in admins]  # Assuming username is email
                            if admin_emails:
                                send_email(
                                    subject="Automated VM Migration",
                                    recipients=admin_emails,
                                    body=f"VM {vm['vmid']} has been migrated from {node} to {target_node} due to high resource usage."
                                )
                            break  # Migrate one VM at a time
                        except Exception as e:
                            log_activity(None, f"Failed automated migration of VM {vm['vmid']} from {node} to {target_node}: {str(e)}")
                            continue
        print("Load balancing check completed.")
    except Exception as e:
        print(f"Error during load balancing: {e}")

def find_least_loaded_node(node_resources, exclude=None, host=None):
    available_nodes = [node for node, res in node_resources.items()
                       if node != exclude and res['host'] != host]
    if not available_nodes:
        return None
    # Sort nodes by CPU and Memory usage
    available_nodes_sorted = sorted(available_nodes, key=lambda node: (node_resources[node]['cpu'], node_resources[node]['memory']))
    return available_nodes_sorted[0] if available_nodes_sorted else None

# Initialize APScheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=load_balance, trigger="interval", minutes=5)  # Adjust interval as needed
scheduler.start()

# Shut down the scheduler when exiting the app
import atexit
atexit.register(lambda: scheduler.shutdown())

# Error Handlers

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"msg": "Bad Request", "error": str(e)}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"msg": "Unauthorized", "error": str(e)}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"msg": "Forbidden", "error": str(e)}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"msg": "Not Found", "error": str(e)}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"msg": "Internal Server Error", "error": str(e)}), 500

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
