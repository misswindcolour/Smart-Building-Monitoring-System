import os
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
    flash
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


USE_HTTPS = os.getenv(
    "USE_HTTPS",
    "false"
).lower() == "true"

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

# Only send session cookie over HTTPS when HTTPS is enabled.
app.config["SESSION_COOKIE_SECURE"] = USE_HTTPS

# Prevent permanent sessions unless explicitly required.
app.config["SESSION_PERMANENT"] = False


# ============================================================
# DATABASE
# ============================================================

def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "railway"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False
    )


# ============================================================
# SECURITY / CACHE HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    # Prevent browser caching of authenticated pages.
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, "
        "max-age=0, private"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Basic browser security headers.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # HSTS should only be sent over HTTPS.
    if USE_HTTPS:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


# ============================================================
# AUTHENTICATION DECORATORS
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


def admin_required(f):

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

        if session.get("role") != "Admin":

            flash(
                "Access restricted to Administrators.",
                "error"
            )

            return redirect(
                url_for("manager_dashboard")
            )

        return f(*args, **kwargs)

    return decorated_function


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    if session.get("role") == "Admin":
        return redirect(
            url_for("admin_dashboard")
        )

    if session.get("role") == "Manager":
        return redirect(
            url_for("manager_dashboard")
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

    # If already logged in, don't show login page.
    if "user_id" in session:

        if session.get("role") == "Admin":
            return redirect(
                url_for("admin_dashboard")
            )

        if session.get("role") == "Manager":
            return redirect(
                url_for("manager_dashboard")
            )

        session.clear()

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

                # Remove any old session information.
                session.clear()

                # Store authenticated user identity.
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]

                if user["role"] == "Admin":

                    return redirect(
                        url_for("admin_dashboard")
                    )

                return redirect(
                    url_for("manager_dashboard")
                )

            flash(
                "Invalid username or password.",
                "error"
            )

        except Exception:

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
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    # Completely destroy authentication session.
    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    response = redirect(
        url_for("login")
    )

    # Explicitly prevent the logout response being cached.
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )

    return response


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

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
                    COALESCE(SUM(quantity), 0)
                        AS total_units,
                    COALESCE(SUM(faulty_count), 0)
                        AS faulty_units
                FROM equipment
                """
            )

            equipment_stats = cursor.fetchone()

            total_equipment = equipment_stats["total_units"]
            faulty_equipment = equipment_stats["faulty_units"]

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
            # ACTIVE BUILDING REQUESTS
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM building_requests
                WHERE status != 'Resolved'
                """
            )

            pending_building_requests = (
                cursor.fetchone()["total"]
            )

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
                    e.faulty_count DESC
                """
            )

            alerts = cursor.fetchall()

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

            # ------------------------------------------------
            # RECENT REQUESTS
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
                    b.building_name,

                    u.username AS requester

                FROM maintenance_requests mr

                JOIN buildings b
                    ON mr.building_id = b.id

                JOIN users u
                    ON mr.requester_id = u.id

                ORDER BY
                    mr.created_at DESC

                LIMIT 5
                """
            )

            recent_requests = cursor.fetchall()

    except Exception:

        total_buildings = 0
        total_equipment = 0
        faulty_equipment = 0
        pending_requests = 0
        pending_building_requests = 0

        alerts = []
        buildings_overview = []
        recent_requests = []

        flash(
            "Unable to load dashboard data.",
            "error"
        )

    finally:

        if db:
            db.close()

    return render_template(
        "admin_dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        total_buildings=total_buildings,
        total_equipment=total_equipment,
        faulty_equipment=faulty_equipment,
        pending_requests=pending_requests,
        pending_building_requests=pending_building_requests,
        alerts=alerts,
        buildings_overview=buildings_overview,
        recent_requests=recent_requests
    )


# ============================================================
# MANAGER DASHBOARD
# ============================================================

@app.route("/manager")
@login_required
def manager_dashboard():

    # Manager is intentionally read-only.
    # Admin is also allowed to view this page if necessary.

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
                    COALESCE(SUM(quantity), 0)
                        AS total_units,
                    COALESCE(SUM(faulty_count), 0)
                        AS faulty_units
                FROM equipment
                """
            )

            equipment_stats = cursor.fetchone()

            total_equipment = equipment_stats["total_units"]
            faulty_equipment = equipment_stats["faulty_units"]

            # ------------------------------------------------
            # RESOLVED REQUESTS
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM maintenance_requests
                WHERE status = 'Resolved'
                """
            )

            resolved_count = cursor.fetchone()["total"]

            # ------------------------------------------------
            # ACTIVE REQUESTS
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM maintenance_requests
                WHERE status != 'Resolved'
                """
            )

            active_requests = cursor.fetchone()["total"]

            # ------------------------------------------------
            # LATEST SENSOR DATA
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    b.building_code,
                    b.building_name,
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

            sensor_telemetry = cursor.fetchall()

            # ------------------------------------------------
            # BUILDING OVERVIEW
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
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

    except Exception:

        total_buildings = 0
        total_equipment = 0
        faulty_equipment = 0
        resolved_count = 0
        active_requests = 0

        sensor_telemetry = []
        buildings_overview = []

        flash(
            "Unable to load manager dashboard.",
            "error"
        )

    finally:

        if db:
            db.close()

    return render_template(
        "manager_dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        total_buildings=total_buildings,
        total_equipment=total_equipment,
        faulty_equipment=faulty_equipment,
        resolved_count=resolved_count,
        active_requests=active_requests,
        sensor_telemetry=sensor_telemetry,
        buildings_overview=buildings_overview
    )


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

    # --------------------------------------------------------
    # ADMIN: ADD EQUIPMENT
    # --------------------------------------------------------

    if request.method == "POST":

        if session.get("role") != "Admin":

            flash(
                "Only administrators can add equipment.",
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

        quantity_raw = request.form.get(
            "quantity",
            "0"
        )

        try:

            quantity = int(quantity_raw)

            if not building_id:
                raise ValueError

            if not equipment_name:
                raise ValueError

            if not equipment_type:
                raise ValueError

            if quantity < 1:
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
                            quantity
                        )
                    VALUES
                        (%s, %s, %s, %s)
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

            flash(
                "Please enter valid equipment information.",
                "error"
            )

        except Exception:

            if db:
                db.rollback()

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

    # --------------------------------------------------------
    # LOAD EQUIPMENT
    # --------------------------------------------------------

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

                ORDER BY
                    building_code
                """
            )

            buildings = cursor.fetchall()

    except Exception:

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
@admin_required
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

                flash(
                    "Equipment record not found.",
                    "error"
                )

                db.rollback()

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

    except Exception:

        if db:
            db.rollback()

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

    except Exception:

        sensor_data = []

        flash(
            "Unable to load sensor data.",
            "error"
        )

    finally:

        if db:
            db.close()

    buildings_dict = {}

    for row in sensor_data:

        building = row["building_name"]

        if building not in buildings_dict:
            buildings_dict[building] = []

        buildings_dict[building].append(row)

    return render_template(
        "sensors.html",
        buildings_dict=buildings_dict,
        role=session.get("role"),
        username=session.get("username")
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

    # --------------------------------------------------------
    # CREATE REQUEST
    # --------------------------------------------------------

    if request.method == "POST":

        # IMPORTANT:
        # Managers are intentionally read-only according
        # to the agreed role requirements.

        if session.get("role") != "Admin":

            flash(
                "Managers have read-only access and cannot submit requests.",
                "error"
            )

            return redirect(
                url_for("maintenance_page")
            )

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

                # ------------------------------------------------
                # BUILDING REQUEST
                # ------------------------------------------------

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
                            (%s, %s, %s, %s, %s)
                        """,
                        (
                            session["user_id"],
                            building_id,
                            building_request_type,
                            details,
                            priority
                        )
                    )

                # ------------------------------------------------
                # EQUIPMENT MAINTENANCE REQUEST
                # ------------------------------------------------

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
                            (%s, %s, %s, %s, %s)
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
                f"Request submitted successfully by {session.get('username')}.",
                "success"
            )

        except Exception:

            if db:
                db.rollback()

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

    # --------------------------------------------------------
    # LOAD REQUESTS
    # --------------------------------------------------------

    try:

        db = get_db()

        with db.cursor() as cursor:

            # ------------------------------------------------
            # MAINTENANCE REQUESTS
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

            # ------------------------------------------------
            # BUILDING REQUESTS
            # ------------------------------------------------

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

            # ------------------------------------------------
            # BUILDINGS
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    building_code,
                    building_name

                FROM buildings

                ORDER BY
                    building_code
                """
            )

            buildings = cursor.fetchall()

            # ------------------------------------------------
            # EQUIPMENT
            # ------------------------------------------------

            cursor.execute(
                """
                SELECT
                    id,
                    building_id,
                    equipment_name

                FROM equipment

                ORDER BY
                    equipment_name
                """
            )

            equipment_list = cursor.fetchall()

    except Exception:

        maintenance_requests = []
        building_requests = []
        buildings = []
        equipment_list = []

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
@admin_required
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

            # ------------------------------------------------
            # CREATE / UPDATE HISTORY WHEN RESOLVED
            # ------------------------------------------------

            if status == "Resolved":

                resolution_details = request.form.get(
                    "resolution_details",
                    ""
                ).strip()

                if not resolution_details:

                    resolution_details = (
                        "Request resolved by administrator."
                    )

                cursor.execute(
                    """
                    SELECT id
                    FROM maintenance_history
                    WHERE request_id = %s
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
                                resolved_by_id,
                                resolution_details
                            )
                        VALUES
                            (%s, %s, %s)
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

    except Exception:

        if db:
            db.rollback()

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
@admin_required
def update_building_request(request_id):

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
            "Invalid building request status.",
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
                SELECT id
                FROM building_requests
                WHERE id = %s
                """,
                (request_id,)
            )

            if not cursor.fetchone():

                flash(
                    "Building request not found.",
                    "error"
                )

                return redirect(
                    url_for("maintenance_page")
                )

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

        db.commit()

        flash(
            "Building request updated successfully.",
            "success"
        )

    except Exception:

        if db:
            db.rollback()

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

                    mr.id AS original_request_id,
                    mr.details AS issue_details,
                    mr.priority,
                    mr.created_at,

                    req_user.username
                        AS requested_by,

                    res_user.username
                        AS resolved_by,

                    b.building_code,
                    b.building_name,

                    e.equipment_name

                FROM maintenance_history mh

                JOIN maintenance_requests mr
                    ON mh.request_id = mr.id

                JOIN users req_user
                    ON mr.requester_id = req_user.id

                JOIN users res_user
                    ON mh.resolved_by_id = res_user.id

                JOIN buildings b
                    ON mr.building_id = b.id

                LEFT JOIN equipment e
                    ON mr.equipment_id = e.id

                ORDER BY
                    mh.resolution_date DESC
                """
            )

            history_logs = cursor.fetchall()

    except Exception:

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
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    if USE_HTTPS:

        # If the user provides a certificate and key,
        # use them.
        if SSL_CERT_FILE and SSL_KEY_FILE:

            ssl_context = (
                SSL_CERT_FILE,
                SSL_KEY_FILE
            )

            print(
                "Starting Flask with configured HTTPS certificate..."
            )

        else:

            # Development HTTPS certificate.
            print(
                "Starting Flask with temporary HTTPS certificate..."
            )

            ssl_context = "adhoc"

        app.run(
            debug=True,
            host="127.0.0.1",
            port=5000,
            ssl_context=ssl_context
        )

    else:

        print(
            "Starting Flask without HTTPS..."
        )

        app.run(
            debug=True,
            host="127.0.0.1",
            port=5000
        )