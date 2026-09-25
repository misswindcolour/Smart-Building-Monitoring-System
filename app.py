import os
import random
from functools import wraps

import pymysql
import pymysql.cursors

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)
from werkzeug.security import check_password_hash


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not configured."
    )

app.secret_key = secret_key

USE_HTTPS = (
    os.getenv("USE_HTTPS", "false").lower() == "true"
)

SSL_CERT_FILE = os.getenv(
    "SSL_CERT_FILE",
    ""
).strip()

SSL_KEY_FILE = os.getenv(
    "SSL_KEY_FILE",
    ""
).strip()


# ============================================================
# SESSION SECURITY
# ============================================================

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = USE_HTTPS
app.config["SESSION_PERMANENT"] = False


# ============================================================
# DATABASE
# ============================================================

def get_db():

    db_ssl_ca = os.getenv(
        "DB_SSL_CA",
        ""
    ).strip()

    connection_options = {
        "host": os.getenv(
            "DB_HOST",
            "localhost"
        ),
        "port": int(
            os.getenv(
                "DB_PORT",
                "3306"
            )
        ),
        "user": os.getenv(
            "DB_USER",
            "root"
        ),
        "password": os.getenv(
            "DB_PASSWORD",
            ""
        ),
        "database": os.getenv(
            "DB_NAME",
            "defaultdb"
        ),
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": False
    }

    # Aiven MySQL requires SSL.
    # The CA certificate path is supplied through .env.
    if db_ssl_ca:

        connection_options["ssl"] = {
            "ca": db_ssl_ca
        }

    return pymysql.connect(
        **connection_options
    )




# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, "
        "max-age=0, private"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    if USE_HTTPS:

        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


# ============================================================
# AUTHENTICATION
# ============================================================

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please log in to continue.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        return f(*args, **kwargs)

    return decorated_function


# ============================================================
# MANAGER-ONLY ACCESS
# ============================================================

def manager_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please log in to continue.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        if session.get("role") != "Manager":

            flash(
                "Access restricted to Managers.",
                "error"
            )

            return redirect(
                url_for("user_dashboard")
            )

        return f(*args, **kwargs)

    return decorated_function


# ============================================================
# BACKWARD-COMPATIBLE ALIAS
# ============================================================

admin_required = manager_required


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    if session.get("role") == "Manager":

        return redirect(
            url_for("manager_dashboard")
        )

    if session.get("role") == "User":

        return redirect(
            url_for("user_dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter both username and password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        db = None

        try:

            db = get_db()

            with db.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT
                        u.id,
                        u.username,
                        u.password_hash,
                        r.role_name AS role
                    FROM users u
                    JOIN roles r
                        ON u.role_id = r.id
                    WHERE u.username = %s
                    """,
                    (username,)
                )

                user = cursor.fetchone()

            if (
                user
                and check_password_hash(
                    user["password_hash"],
                    password
                )
            ):

                session.clear()

                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]

                if user["role"] == "Manager":

                    return redirect(
                        url_for("manager_dashboard")
                    )

                if user["role"] == "User":

                    return redirect(
                        url_for("user_dashboard")
                    )

                flash(
                    "Invalid account role.",
                    "error"
                )

            else:

                flash(
                    "Invalid username or password.",
                    "error"
                )

        except Exception as e:

            print(
                "LOGIN DATABASE ERROR:",
                repr(e)
            )

            flash(
                "Unable to connect to the database.",
                "error"
            )

        finally:

            if db:
                db.close()

    return render_template(
        "login.html"
    )


# ============================================================
# MANAGER DASHBOARD
# ============================================================

@app.route("/manager")
@manager_required
def manager_dashboard():

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            # ------------------------------------------------
            # BUILDINGS
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM buildings
                """
            )

            total_buildings = cursor.fetchone()["total"]

            # ------------------------------------------------
            # EQUIPMENT
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(quantity), 0) AS total,
                    COALESCE(SUM(faulty_count), 0) AS faulty
                FROM equipment
                """
            )

            equipment_stats = cursor.fetchone()

            total_equipment = (
                equipment_stats["total"] or 0
            )

            faulty_equipment = (
                equipment_stats["faulty"] or 0
            )

            # ------------------------------------------------
            # ACTIVE MAINTENANCE
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM maintenance_requests
                WHERE status != 'Resolved'
                """
            )

            pending_requests = cursor.fetchone()["total"]

            # ------------------------------------------------
            # SENSOR ALERT COUNT
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    b.building_code,
                    b.building_name,
                    s.id AS sensor_id,
                    s.sensor_type,
                    s.status,
                    sr.reading_value,
                    sr.timestamp
                FROM sensors s
                JOIN buildings b
                    ON s.building_id = b.id
                LEFT JOIN (
                    SELECT
                        sensor_id,
                        MAX(timestamp) AS max_time
                    FROM sensor_readings
                    GROUP BY sensor_id
                ) latest
                    ON s.id = latest.sensor_id
                LEFT JOIN sensor_readings sr
                    ON s.id = sr.sensor_id
                    AND sr.timestamp = latest.max_time
                ORDER BY
                    b.building_code,
                    s.sensor_type
                """
            )

            sensor_rows = cursor.fetchall()

            # ------------------------------------------------
            # EQUIPMENT ALERTS
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    e.*,
                    b.building_code,
                    b.building_name
                FROM equipment e
                JOIN buildings b
                    ON e.building_id = b.id
                WHERE
                    e.status IN ('Faulty', 'Maintenance')
                    OR e.faulty_count > 0
                ORDER BY
                    e.faulty_count DESC,
                    b.building_code
                """
            )

            equipment_alerts = cursor.fetchall()

            # ------------------------------------------------
            # RECENT MAINTENANCE
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    mr.id,
                    mr.details,
                    mr.priority,
                    mr.status,
                    mr.created_at,
                    b.building_code,
                    u.username AS requester
                FROM maintenance_requests mr
                JOIN buildings b
                    ON mr.building_id = b.id
                JOIN users u
                    ON mr.requester_id = u.id
                ORDER BY
                    mr.created_at DESC
                LIMIT 8
                """
            )

            recent_requests = cursor.fetchall()

            # ------------------------------------------------
            # BUILDING OVERVIEW
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    b.id,
                    b.building_code,
                    b.building_name,
                    b.capacity,
                    COALESCE(
                        SUM(e.quantity),
                        0
                    ) AS equipment_units,
                    COALESCE(
                        SUM(e.faulty_count),
                        0
                    ) AS faulty_count
                FROM buildings b
                LEFT JOIN equipment e
                    ON b.id = e.building_id
                GROUP BY
                    b.id,
                    b.building_code,
                    b.building_name,
                    b.capacity
                ORDER BY
                    b.building_code
                """
            )

            buildings_overview = cursor.fetchall()

    except Exception as e:

        print(
            "MANAGER DASHBOARD ERROR:",
            repr(e)
        )

        total_buildings = 0
        total_equipment = 0
        faulty_equipment = 0
        pending_requests = 0

        sensor_rows = []
        equipment_alerts = []
        recent_requests = []
        buildings_overview = []

        flash(
            "Unable to load dashboard data.",
            "error"
        )

    finally:

        if db:
            db.close()

    sensor_alerts = build_sensor_alerts(
        sensor_rows
    )

    return render_template(
        "manager_dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        total_buildings=total_buildings,
        total_equipment=total_equipment,
        faulty_equipment=faulty_equipment,
        pending_requests=pending_requests,
        sensor_alerts=sensor_alerts,
        equipment_alerts=equipment_alerts,
        recent_requests=recent_requests,
        buildings_overview=buildings_overview
    )


# ============================================================
# USER DASHBOARD
# ============================================================

@app.route("/user")
@login_required
def user_dashboard():

    if session.get("role") != "User":

        if session.get("role") == "Manager":

            return redirect(
                url_for("manager_dashboard")
            )

        return redirect(
            url_for("login")
        )

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM buildings
                """
            )

            total_buildings = cursor.fetchone()["total"]

            cursor.execute(
                """
                SELECT
                    COALESCE(SUM(quantity), 0) AS total,
                    COALESCE(SUM(faulty_count), 0) AS faulty
                FROM equipment
                """
            )

            stats = cursor.fetchone()

            total_equipment = stats["total"] or 0
            faulty_equipment = stats["faulty"] or 0

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM maintenance_requests
                WHERE status != 'Resolved'
                """
            )

            active_requests = cursor.fetchone()["total"]

            cursor.execute(
                """
                SELECT
                    b.building_code,
                    b.building_name,
                    s.id AS sensor_id,
                    s.sensor_type,
                    s.status,
                    sr.reading_value,
                    sr.timestamp
                FROM sensors s
                JOIN buildings b
                    ON s.building_id = b.id
                LEFT JOIN (
                    SELECT
                        sensor_id,
                        MAX(timestamp) AS max_time
                    FROM sensor_readings
                    GROUP BY sensor_id
                ) latest
                    ON s.id = latest.sensor_id
                LEFT JOIN sensor_readings sr
                    ON s.id = sr.sensor_id
                    AND sr.timestamp = latest.max_time
                ORDER BY
                    b.building_code,
                    s.sensor_type
                """
            )

            sensor_rows = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    mr.id,
                    mr.details,
                    mr.priority,
                    mr.status,
                    mr.created_at,
                    b.building_code
                FROM maintenance_requests mr
                JOIN buildings b
                    ON mr.building_id = b.id
                WHERE mr.requester_id = %s
                ORDER BY mr.created_at DESC
                LIMIT 8
                """,
                (session["user_id"],)
            )

            my_requests = cursor.fetchall()

    except Exception as e:

        print(
            "USER DASHBOARD ERROR:",
            repr(e)
        )

        total_buildings = 0
        total_equipment = 0
        faulty_equipment = 0
        active_requests = 0
        sensor_rows = []
        my_requests = []

        flash(
            "Unable to load dashboard data.",
            "error"
        )

    finally:

        if db:
            db.close()

    sensor_alerts = build_sensor_alerts(
        sensor_rows
    )

    return render_template(
        "user_dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        total_buildings=total_buildings,
        total_equipment=total_equipment,
        faulty_equipment=faulty_equipment,
        active_requests=active_requests,
        sensor_alerts=sensor_alerts,
        my_requests=my_requests
    )


# ============================================================
# SENSOR THRESHOLDS
# ============================================================

SENSOR_THRESHOLDS = {

    "Temperature": {
        "unit": "°C",
        "critical_low": 15.0,
        "warning_low": 18.0,
        "normal_high": 28.0,
        "critical_high": 32.0
    },

    "Humidity": {
        "unit": "%",
        "critical_low": 20.0,
        "warning_low": 30.0,
        "normal_high": 60.0,
        "critical_high": 70.0
    },

    "Air Quality": {
        "unit": "AQI",
        "critical_low": None,
        "warning_low": None,
        "normal_high": 50.0,
        "critical_high": 100.0
    }
}


def get_sensor_status(
    sensor_type,
    sensor_status,
    value
):

    if sensor_status == "Maintenance":
        return "Maintenance"

    if sensor_status == "Offline":
        return "Offline"

    if value is None:
        return "Offline"

    threshold = SENSOR_THRESHOLDS.get(
        sensor_type
    )

    if not threshold:
        return "Normal"

    critical_low = threshold["critical_low"]
    warning_low = threshold["warning_low"]
    normal_high = threshold["normal_high"]
    critical_high = threshold["critical_high"]

    if (
        critical_low is not None
        and value < critical_low
    ):
        return "Critical"

    if (
        warning_low is not None
        and value < warning_low
    ):
        return "Warning"

    if (
        critical_high is not None
        and value > critical_high
    ):
        return "Critical"

    if (
        normal_high is not None
        and value > normal_high
    ):
        return "Warning"

    return "Normal"


def build_sensor_alerts(sensor_rows):

    alerts = []

    for row in sensor_rows:

        value = row.get(
            "reading_value"
        )

        sensor_status = get_sensor_status(
            row["sensor_type"],
            row["status"],
            value
        )

        if sensor_status in [
            "Warning",
            "Critical",
            "Offline",
            "Maintenance"
        ]:

            threshold = SENSOR_THRESHOLDS.get(
                row["sensor_type"],
                {}
            )

            alerts.append({
                "sensor_id": row["sensor_id"],
                "building_code": row["building_code"],
                "building_name": row["building_name"],
                "sensor_type": row["sensor_type"],
                "reading_value": value,
                "timestamp": row["timestamp"],
                "sensor_status": sensor_status,
                "unit": threshold.get(
                    "unit",
                    ""
                )
            })

    severity_order = {
        "Critical": 1,
        "Offline": 2,
        "Maintenance": 3,
        "Warning": 4
    }

    alerts.sort(
        key=lambda x:
        severity_order.get(
            x["sensor_status"],
            99
        )
    )

    return alerts


# ============================================================
# SENSORS
# ============================================================

@app.route("/sensors")
@login_required
def sensors_page():

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    b.id AS building_id,
                    b.building_code,
                    b.building_name,

                    s.id AS sensor_id,
                    s.sensor_type,
                    s.status,

                    sr.reading_value,
                    sr.timestamp

                FROM sensors s

                JOIN buildings b
                    ON s.building_id = b.id

                LEFT JOIN (
                    SELECT
                        sensor_id,
                        MAX(timestamp) AS max_time
                    FROM sensor_readings
                    GROUP BY sensor_id
                ) latest
                    ON s.id = latest.sensor_id

                LEFT JOIN sensor_readings sr
                    ON s.id = sr.sensor_id
                    AND sr.timestamp = latest.max_time

                ORDER BY
                    b.building_code,
                    s.sensor_type
                """
            )

            sensor_data = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id,
                    building_code,
                    building_name
                FROM buildings
                ORDER BY building_code
                """
            )

            buildings = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    b.building_code,
                    b.building_name,
                    s.id AS sensor_id,
                    s.sensor_type,
                    sr.reading_value,
                    sr.timestamp
                FROM sensor_readings sr
                JOIN sensors s
                    ON sr.sensor_id = s.id
                JOIN buildings b
                    ON s.building_id = b.id
                WHERE s.sensor_type = 'Temperature'
                ORDER BY
                    sr.timestamp ASC
                """
            )

            temperature_rows = cursor.fetchall()

    except Exception as e:

        print(
            "SENSOR PAGE ERROR:",
            repr(e)
        )

        sensor_data = []
        buildings = []
        temperature_rows = []

        flash(
            "Unable to load sensor data.",
            "error"
        )

    finally:

        if db:
            db.close()

    for row in sensor_data:

        row["calculated_status"] = get_sensor_status(
            row["sensor_type"],
            row["status"],
            row["reading_value"]
        )

    buildings_dict = {}

    for row in sensor_data:

        building = row["building_name"]

        if building not in buildings_dict:

            buildings_dict[building] = []

        buildings_dict[building].append(row)

    building_statuses = {}

    severity = {
        "Critical": 4,
        "Offline": 3,
        "Maintenance": 2,
        "Warning": 1,
        "Normal": 0
    }

    for building, sensors in buildings_dict.items():

        worst = "Normal"

        for sensor in sensors:

            current = sensor["calculated_status"]

            if severity.get(
                current,
                0
            ) > severity.get(
                worst,
                0
            ):

                worst = current

        building_statuses[building] = worst

    sensor_alerts = build_sensor_alerts(
        sensor_data
    )

    temperature_chart = []

    for row in temperature_rows:

        temperature_chart.append({
            "building_code": row["building_code"],
            "building_name": row["building_name"],
            "sensor_id": row["sensor_id"],
            "value": float(
                row["reading_value"]
            ),
            "timestamp": row["timestamp"].strftime(
                "%Y-%m-%d %H:%M"
            )
        })

    return render_template(
        "sensors.html",
        buildings_dict=buildings_dict,
        building_statuses=building_statuses,
        sensor_alerts=sensor_alerts,
        buildings=buildings,
        temperature_chart=temperature_chart,
        thresholds=SENSOR_THRESHOLDS,
        role=session.get("role"),
        username=session.get("username")
    )


# ============================================================
# TEMPERATURE HISTORY API
# ============================================================

def ensure_temperature_demo_readings(cursor):

    cursor.execute(
        """
        SELECT
            s.id,
            s.building_id
        FROM sensors s
        WHERE s.sensor_type = 'Temperature'
          AND s.status != 'Maintenance'
        """
    )

    sensors = cursor.fetchall()

    for sensor in sensors:

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM sensor_readings
            WHERE sensor_id = %s
            """,
            (sensor["id"],)
        )

        total = cursor.fetchone()["total"] or 0

        if total == 0:

            base = random.uniform(
                21.0,
                25.0
            )

            for minutes_ago in [
                360,
                330,
                300,
                270,
                240,
                210,
                180,
                150,
                120,
                90,
                60,
                30,
                0
            ]:

                value = round(
                    base + random.uniform(
                        -1.5,
                        1.5
                    ),
                    1
                )

                cursor.execute(
                    """
                    INSERT INTO sensor_readings
                        (
                            sensor_id,
                            reading_value,
                            timestamp
                        )
                    VALUES
                        (
                            %s,
                            %s,
                            DATE_SUB(
                                NOW(),
                                INTERVAL %s MINUTE
                            )
                        )
                    """,
                    (
                        sensor["id"],
                        value,
                        minutes_ago
                    )
                )


@app.route("/api/temperature-history")
@login_required
def temperature_history():

    building_id = request.args.get(
        "building_id"
    )

    hours = request.args.get(
        "hours",
        "24"
    )

    try:

        hours = int(hours)

    except ValueError:

        hours = 24

    allowed_hours = [
        6,
        12,
        24,
        48,
        168
    ]

    if hours not in allowed_hours:

        hours = 24

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            ensure_temperature_demo_readings(
                cursor
            )

            db.commit()

            if building_id:

                cursor.execute(
                    """
                    SELECT
                        b.building_code,
                        b.building_name,
                        s.id AS sensor_id,
                        sr.reading_value,
                        sr.timestamp
                    FROM sensor_readings sr
                    JOIN sensors s
                        ON sr.sensor_id = s.id
                    JOIN buildings b
                        ON s.building_id = b.id
                    WHERE
                        s.sensor_type = 'Temperature'
                        AND b.id = %s
                        AND sr.timestamp >=
                            DATE_SUB(
                                NOW(),
                                INTERVAL %s HOUR
                            )
                    ORDER BY
                        sr.timestamp ASC
                    """,
                    (
                        building_id,
                        hours
                    )
                )

            else:

                cursor.execute(
                    """
                    SELECT
                        b.building_code,
                        b.building_name,
                        s.id AS sensor_id,
                        sr.reading_value,
                        sr.timestamp
                    FROM sensor_readings sr
                    JOIN sensors s
                        ON sr.sensor_id = s.id
                    JOIN buildings b
                        ON s.building_id = b.id
                    WHERE
                        s.sensor_type = 'Temperature'
                        AND sr.timestamp >=
                            DATE_SUB(
                                NOW(),
                                INTERVAL %s HOUR
                            )
                    ORDER BY
                        sr.timestamp ASC
                    """,
                    (hours,)
                )

            rows = cursor.fetchall()

    except Exception as e:

        print(
            "TEMPERATURE HISTORY ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "message": "Unable to load temperature history."
        }), 500

    finally:

        if db:
            db.close()

    data = []

    for row in rows:

        data.append({
            "building_code": row["building_code"],
            "building_name": row["building_name"],
            "sensor_id": row["sensor_id"],
            "value": float(
                row["reading_value"]
            ),
            "timestamp": row["timestamp"].strftime(
                "%Y-%m-%d %H:%M"
            )
        })

    return jsonify({
        "success": True,
        "data": data
    })


# ============================================================
# EQUIPMENT
# ============================================================

@app.route(
    "/equipment",
    methods=["GET", "POST"]
)
@login_required
def equipment_page():

    db = None

    if request.method == "POST":

        if session.get("role") != "Manager":

            flash(
                "Only Managers can add equipment.",
                "error"
            )

            return redirect(
                url_for("equipment_page")
            )

        building_id = request.form.get(
            "building_id"
        )

        equipment_name = request.form.get(
            "equipment_name",
            ""
        ).strip()

        equipment_type = request.form.get(
            "equipment_type",
            ""
        ).strip()

        try:

            quantity = int(
                request.form.get(
                    "quantity",
                    "0"
                )
            )

            if quantity < 1:
                raise ValueError

            if not building_id:
                raise ValueError

            if not equipment_name:
                raise ValueError

            db = get_db()

            with db.cursor() as cursor:

                cursor.execute(
                    """
                    INSERT INTO equipment
                        (
                            building_id,
                            equipment_name,
                            equipment_type,
                            quantity,
                            status,
                            faulty_count
                        )
                    VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s,
                            'Working',
                            0
                        )
                    """,
                    (
                        building_id,
                        equipment_name,
                        equipment_type,
                        quantity
                    )
                )

            db.commit()

            flash(
                "Equipment added successfully.",
                "success"
            )

        except ValueError:

            if db:
                db.rollback()

            flash(
                "Please enter valid equipment information.",
                "error"
            )

        except Exception as e:

            if db:
                db.rollback()

            print(
                "ADD EQUIPMENT ERROR:",
                repr(e)
            )

            flash(
                "Unable to add equipment.",
                "error"
            )

        finally:

            if db:
                db.close()

        return redirect(
            url_for("equipment_page")
        )

    try:

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    e.*,
                    b.building_code,
                    b.building_name
                FROM equipment e
                JOIN buildings b
                    ON e.building_id = b.id
                ORDER BY
                    b.building_code,
                    e.equipment_name
                """
            )

            equipment_list = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id,
                    building_code,
                    building_name
                FROM buildings
                ORDER BY building_code
                """
            )

            buildings = cursor.fetchall()

    except Exception as e:

        print(
            "EQUIPMENT PAGE ERROR:",
            repr(e)
        )

        equipment_list = []
        buildings = []

        flash(
            "Unable to load equipment.",
            "error"
        )

    finally:

        if db:
            db.close()

    return render_template(
        "equipment.html",
        equipment_list=equipment_list,
        buildings=buildings,
        role=session.get("role"),
        username=session.get("username")
    )


# ============================================================
# UPDATE EQUIPMENT
# ============================================================

@app.route(
    "/equipment/update/<int:equipment_id>",
    methods=["POST"]
)
@manager_required
def update_equipment(equipment_id):

    db = None

    try:

        quantity = int(
            request.form.get(
                "quantity",
                "0"
            )
        )

        faulty_count = int(
            request.form.get(
                "faulty_count",
                "0"
            )
        )

        status = request.form.get(
            "status"
        )

        valid_statuses = [
            "Working",
            "Maintenance",
            "Faulty"
        ]

        if quantity < 1:
            raise ValueError

        if faulty_count < 0:
            raise ValueError

        if faulty_count > quantity:
            raise ValueError

        if status not in valid_statuses:
            raise ValueError

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                UPDATE equipment
                SET
                    quantity = %s,
                    faulty_count = %s,
                    status = %s
                WHERE id = %s
                """,
                (
                    quantity,
                    faulty_count,
                    status,
                    equipment_id
                )
            )

            if cursor.rowcount == 0:

                db.rollback()

                flash(
                    "Equipment record not found.",
                    "error"
                )

                return redirect(
                    url_for("equipment_page")
                )

        db.commit()

        flash(
            "Equipment record updated successfully.",
            "success"
        )

    except ValueError:

        flash(
            "Invalid equipment values. Faulty quantity cannot exceed total quantity.",
            "error"
        )

    except Exception as e:

        if db:
            db.rollback()

        print(
            "UPDATE EQUIPMENT ERROR:",
            repr(e)
        )

        flash(
            "Failed to update equipment.",
            "error"
        )

    finally:

        if db:
            db.close()

    return redirect(
        url_for("equipment_page")
    )


# ============================================================
# MAINTENANCE
# ============================================================

@app.route(
    "/maintenance",
    methods=["GET", "POST"]
)
@login_required
def maintenance_page():

    db = None

    if request.method == "POST":

        request_type = request.form.get(
            "request_type",
            "maintenance"
        )

        building_id = request.form.get(
            "building_id"
        )

        equipment_id = request.form.get(
            "equipment_id"
        )

        details = request.form.get(
            "details",
            ""
        ).strip()

        priority = request.form.get(
            "priority",
            "Normal"
        )

        if not building_id or not details:

            flash(
                "Building and request details are required.",
                "error"
            )

            return redirect(
                url_for("maintenance_page")
            )

        if priority not in [
            "Normal",
            "High",
            "Urgent"
        ]:

            flash(
                "Invalid priority.",
                "error"
            )

            return redirect(
                url_for("maintenance_page")
            )

        try:

            db = get_db()

            with db.cursor() as cursor:

                if request_type == "building":

                    building_request_type = request.form.get(
                        "building_request_type",
                        "General Building Request"
                    ).strip()

                    if not building_request_type:

                        building_request_type = (
                            "General Building Request"
                        )

                    cursor.execute(
                        """
                        INSERT INTO building_requests
                            (
                                requester_id,
                                building_id,
                                request_type,
                                details,
                                priority
                            )
                        VALUES
                            (
                                %s,
                                %s,
                                %s,
                                %s,
                                %s
                            )
                        """,
                        (
                            session["user_id"],
                            building_id,
                            building_request_type,
                            details,
                            priority
                        )
                    )

                else:

                    equipment_value = (
                        equipment_id
                        if equipment_id
                        else None
                    )

                    cursor.execute(
                        """
                        INSERT INTO maintenance_requests
                            (
                                requester_id,
                                building_id,
                                equipment_id,
                                details,
                                priority
                            )
                        VALUES
                            (
                                %s,
                                %s,
                                %s,
                                %s,
                                %s
                            )
                        """,
                        (
                            session["user_id"],
                            building_id,
                            equipment_value,
                            details,
                            priority
                        )
                    )

            db.commit()

            flash(
                "Request submitted successfully.",
                "success"
            )

        except Exception as e:

            if db:
                db.rollback()

            print(
                "SUBMIT REQUEST ERROR:",
                repr(e)
            )

            flash(
                "Unable to submit request.",
                "error"
            )

        finally:

            if db:
                db.close()

        return redirect(
            url_for("maintenance_page")
        )

    maintenance_requests = []
    building_requests = []
    buildings = []
    equipment_list = []

    try:

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    mr.id,
                    mr.details,
                    mr.priority,
                    mr.status,
                    mr.created_at,

                    b.building_code,
                    b.building_name,

                    e.equipment_name,

                    u.username AS requester

                FROM maintenance_requests mr

                JOIN buildings b
                    ON mr.building_id = b.id

                LEFT JOIN equipment e
                    ON mr.equipment_id = e.id

                JOIN users u
                    ON mr.requester_id = u.id

                ORDER BY
                    CASE mr.priority
                        WHEN 'Urgent' THEN 1
                        WHEN 'High' THEN 2
                        ELSE 3
                    END,
                    mr.created_at DESC
                """
            )

            maintenance_requests = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    br.id,
                    br.request_type,
                    br.details,
                    br.priority,
                    br.status,
                    br.created_at,

                    b.building_code,
                    b.building_name,

                    u.username AS requester

                FROM building_requests br

                JOIN buildings b
                    ON br.building_id = b.id

                JOIN users u
                    ON br.requester_id = u.id

                ORDER BY
                    br.created_at DESC
                """
            )

            building_requests = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id,
                    building_code,
                    building_name
                FROM buildings
                ORDER BY building_code
                """
            )

            buildings = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id,
                    building_id,
                    equipment_name
                FROM equipment
                ORDER BY equipment_name
                """
            )

            equipment_list = cursor.fetchall()

    except Exception as e:

        print(
            "MAINTENANCE PAGE ERROR:",
            repr(e)
        )

        flash(
            "Unable to load maintenance data.",
            "error"
        )

    finally:

        if db:
            db.close()

    return render_template(
        "maintenance.html",
        maintenance_requests=maintenance_requests,
        building_requests=building_requests,
        buildings=buildings,
        equipment_list=equipment_list,
        role=session.get("role"),
        username=session.get("username")
    )


# ============================================================
# UPDATE MAINTENANCE STATUS
# ============================================================

@app.route(
    "/maintenance/update/<int:request_id>",
    methods=["POST"]
)
@manager_required
def update_maintenance(request_id):

    status = request.form.get(
        "status"
    )

    valid_statuses = [
        "Pending",
        "In Progress",
        "Resolved"
    ]

    if status not in valid_statuses:

        flash(
            "Invalid maintenance status.",
            "error"
        )

        return redirect(
            url_for("maintenance_page")
        )

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                SELECT status
                FROM maintenance_requests
                WHERE id = %s
                """,
                (request_id,)
            )

            current = cursor.fetchone()

            if not current:

                flash(
                    "Maintenance request not found.",
                    "error"
                )

                return redirect(
                    url_for("maintenance_page")
                )

            cursor.execute(
                """
                UPDATE maintenance_requests
                SET status = %s
                WHERE id = %s
                """,
                (
                    status,
                    request_id
                )
            )

            if status == "Resolved":

                resolution_details = request.form.get(
                    "resolution_details",
                    ""
                ).strip()

                if not resolution_details:

                    resolution_details = (
                        "Request resolved by Manager."
                    )

                cursor.execute(
                    """
                    SELECT id
                    FROM maintenance_history
                    WHERE request_id = %s
                    LIMIT 1
                    """,
                    (request_id,)
                )

                existing_history = cursor.fetchone()

                if existing_history:

                    cursor.execute(
                        """
                        UPDATE maintenance_history
                        SET
                            resolved_by_id = %s,
                            resolution_details = %s,
                            resolution_date = NOW()
                        WHERE request_id = %s
                        """,
                        (
                            session["user_id"],
                            resolution_details,
                            request_id
                        )
                    )

                else:

                    cursor.execute(
                        """
                        INSERT INTO maintenance_history
                            (
                                request_id,
                                building_request_id,
                                resolved_by_id,
                                resolution_details,
                                resolution_date
                            )
                        VALUES
                            (
                                %s,
                                NULL,
                                %s,
                                %s,
                                NOW()
                            )
                        """,
                        (
                            request_id,
                            session["user_id"],
                            resolution_details
                        )
                    )

        db.commit()

        flash(
            "Maintenance request updated successfully.",
            "success"
        )

    except Exception as e:

        if db:
            db.rollback()

        print(
            "=" * 60
        )
        print(
            "MAINTENANCE UPDATE ERROR"
        )
        print(
            "Request ID:",
            request_id
        )
        print(
            "Status:",
            status
        )
        print(
            "Error:",
            repr(e)
        )
        print(
            "=" * 60
        )

        flash(
            "Unable to update maintenance request.",
            "error"
        )

    finally:

        if db:
            db.close()

    return redirect(
        url_for("maintenance_page")
    )


# ============================================================
# UPDATE BUILDING REQUEST
# ============================================================

@app.route(
    "/building-request/update/<int:request_id>",
    methods=["POST"]
)
@manager_required
def update_building_request(request_id):

    status = request.form.get(
        "status",
        ""
    ).strip()

    valid_statuses = [
        "Pending",
        "In Progress",
        "Resolved"
    ]

    if status not in valid_statuses:

        flash(
            "Invalid building request status.",
            "error"
        )

        return redirect(
            url_for("maintenance_page")
        )

    resolution_details = request.form.get(
        "resolution_details",
        ""
    ).strip()

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            # ------------------------------------------------
            # FIND BUILDING REQUEST
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    requester_id,
                    building_id,
                    request_type,
                    status
                FROM building_requests
                WHERE id = %s
                """,
                (request_id,)
            )

            building_request = cursor.fetchone()

            if not building_request:

                flash(
                    "Building request not found.",
                    "error"
                )

                return redirect(
                    url_for("maintenance_page")
                )

            # ------------------------------------------------
            # UPDATE BUILDING REQUEST
            # ------------------------------------------------

            cursor.execute(
                """
                UPDATE building_requests
                SET status = %s
                WHERE id = %s
                """,
                (
                    status,
                    request_id
                )
            )

            # ------------------------------------------------
            # CREATE / UPDATE HISTORY WHEN RESOLVED
            # ------------------------------------------------

            if status == "Resolved":

                if not resolution_details:

                    resolution_details = (
                        "Building request resolved by Manager."
                    )

                # ------------------------------------------------
                # CHECK EXISTING BUILDING REQUEST HISTORY
                # ------------------------------------------------

                cursor.execute(
                    """
                    SELECT id
                    FROM maintenance_history
                    WHERE building_request_id = %s
                    LIMIT 1
                    """,
                    (request_id,)
                )

                existing_history = cursor.fetchone()

                # ------------------------------------------------
                # UPDATE EXISTING HISTORY
                # ------------------------------------------------

                if existing_history:

                    cursor.execute(
                        """
                        UPDATE maintenance_history
                        SET
                            resolved_by_id = %s,
                            resolution_details = %s,
                            resolution_date = NOW()
                        WHERE building_request_id = %s
                        """,
                        (
                            session["user_id"],
                            resolution_details,
                            request_id
                        )
                    )

                # ------------------------------------------------
                # CREATE NEW BUILDING REQUEST HISTORY
                # ------------------------------------------------

                else:

                    cursor.execute(
                        """
                        INSERT INTO maintenance_history
                            (
                                request_id,
                                building_request_id,
                                resolved_by_id,
                                resolution_details,
                                resolution_date
                            )
                        VALUES
                            (
                                NULL,
                                %s,
                                %s,
                                %s,
                                NOW()
                            )
                        """,
                        (
                            request_id,
                            session["user_id"],
                            resolution_details
                        )
                    )

        db.commit()

        flash(
            "Building request updated successfully.",
            "success"
        )

    except Exception as e:

        if db:
            db.rollback()

        print(
            "=" * 60
        )
        print(
            "BUILDING REQUEST UPDATE ERROR"
        )
        print(
            "Request ID:",
            request_id
        )
        print(
            "Status:",
            status
        )
        print(
            "Error:",
            repr(e)
        )
        print(
            "=" * 60
        )

        flash(
            "Unable to update building request.",
            "error"
        )

    finally:

        if db:
            db.close()

    return redirect(
        url_for("maintenance_page")
    )


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
@login_required
def history_page():

    db = None

    try:

        db = get_db()

        with db.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    mh.id,
                    mh.resolution_date,
                    mh.resolution_details,

                    COALESCE(
                        mr.id,
                        br.id
                    ) AS original_request_id,

                    COALESCE(
                        mr.details,
                        br.details
                    ) AS issue_details,

                    COALESCE(
                        mr.priority,
                        br.priority
                    ) AS priority,

                    COALESCE(
                        mr.created_at,
                        br.created_at
                    ) AS created_at,

                    COALESCE(
                        br.request_type,
                        'Equipment / Maintenance'
                    ) AS request_type,

                    req_user.username AS requested_by,
                    res_user.username AS resolved_by,

                    b.building_code,
                    b.building_name,

                    e.equipment_name

                FROM maintenance_history mh

                LEFT JOIN maintenance_requests mr
                    ON mh.request_id = mr.id

                LEFT JOIN building_requests br
                    ON mh.building_request_id = br.id

                JOIN users req_user
                    ON req_user.id =
                       COALESCE(
                           mr.requester_id,
                           br.requester_id
                       )

                JOIN users res_user
                    ON mh.resolved_by_id = res_user.id

                JOIN buildings b
                    ON b.id =
                       COALESCE(
                           mr.building_id,
                           br.building_id
                       )

                LEFT JOIN equipment e
                    ON mr.equipment_id = e.id

                ORDER BY
                    mh.resolution_date DESC
                """
            )

            history_logs = cursor.fetchall()

    except Exception as e:

        print(
            "HISTORY PAGE ERROR:",
            repr(e)
        )

        history_logs = []

        flash(
            "Unable to load maintenance history.",
            "error"
        )

    finally:

        if db:
            db.close()

    return render_template(
        "history.html",
        history_logs=history_logs,
        role=session.get("role"),
        username=session.get("username")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    response = redirect(
        url_for("login")
    )

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, "
        "max-age=0, private"
    )

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

# ============================================================
# HEALTH CHECK
# ============================================================
@app.route("/health")
def health():
    """Lightweight health check for Render."""
    return jsonify({
        "success": True,
        "status": "healthy"
    }), 200


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    if USE_HTTPS:

        if SSL_CERT_FILE and SSL_KEY_FILE:

            app.run(
                host="0.0.0.0",
                port=5000,
                debug=True,
                ssl_context=(
                    SSL_CERT_FILE,
                    SSL_KEY_FILE
                )
            )

        else:

            app.run(
                host="0.0.0.0",
                port=5000,
                debug=True,
                ssl_context="adhoc"
            )

    else:

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=True
        )