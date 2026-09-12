import os
import random
import pymysql

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()


def init_database():

    db_name = os.getenv("DB_NAME", "railway")

    connection = pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", "")
    )

    try:
        with connection.cursor() as cursor:
            cursor.execute(f"USE `{db_name}`")

            # ---------------------------------------------------------
            # ROLES
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    role_name VARCHAR(50) NOT NULL UNIQUE
                )
            """)

            # ---------------------------------------------------------
            # USERS
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role_id INT NOT NULL,
                    FOREIGN KEY (role_id) REFERENCES roles(id)
                )
            """)

            # ---------------------------------------------------------
            # BUILDINGS
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS buildings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    building_code VARCHAR(10) NOT NULL UNIQUE,
                    building_name VARCHAR(100) NOT NULL,
                    capacity INT NOT NULL
                )
            """)

            # ---------------------------------------------------------
            # EQUIPMENT
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS equipment (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    building_id INT NOT NULL,
                    equipment_name VARCHAR(100) NOT NULL,
                    equipment_type VARCHAR(100),
                    quantity INT NOT NULL DEFAULT 1,
                    status ENUM(
                        'Working',
                        'Maintenance',
                        'Faulty'
                    ) DEFAULT 'Working',
                    faulty_count INT NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id)
                        ON DELETE CASCADE,

                    CHECK (quantity >= 1),
                    CHECK (faulty_count >= 0),
                    CHECK (faulty_count <= quantity)
                )
            """)

            # ---------------------------------------------------------
            # SENSORS
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sensors (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    building_id INT NOT NULL,
                    sensor_type ENUM(
                        'Temperature',
                        'Humidity',
                        'Air Quality'
                    ) NOT NULL,
                    status ENUM(
                        'Online',
                        'Offline',
                        'Maintenance'
                    ) DEFAULT 'Online',

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id)
                        ON DELETE CASCADE
                )
            """)

            # ---------------------------------------------------------
            # SENSOR READINGS
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sensor_readings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sensor_id INT NOT NULL,
                    reading_value FLOAT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (sensor_id)
                        REFERENCES sensors(id)
                        ON DELETE CASCADE
                )
            """)

            # ---------------------------------------------------------
            # MAINTENANCE REQUESTS
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS maintenance_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    requester_id INT NOT NULL,
                    building_id INT NOT NULL,
                    equipment_id INT NULL,
                    details TEXT NOT NULL,

                    priority ENUM(
                        'Normal',
                        'High',
                        'Urgent'
                    ) DEFAULT 'Normal',

                    status ENUM(
                        'Pending',
                        'In Progress',
                        'Resolved'
                    ) DEFAULT 'Pending',

                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (requester_id)
                        REFERENCES users(id),

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id),

                    FOREIGN KEY (equipment_id)
                        REFERENCES equipment(id)
                        ON DELETE SET NULL
                )
            """)

            # ---------------------------------------------------------
            # BUILDING REQUESTS
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS building_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    requester_id INT NOT NULL,
                    building_id INT NOT NULL,
                    request_type VARCHAR(100) NOT NULL,
                    details TEXT NOT NULL,

                    priority ENUM(
                        'Normal',
                        'High',
                        'Urgent'
                    ) DEFAULT 'Normal',

                    status ENUM(
                        'Pending',
                        'In Progress',
                        'Resolved'
                    ) DEFAULT 'Pending',

                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (requester_id)
                        REFERENCES users(id),

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id)
                )
            """)

            # ---------------------------------------------------------
            # MAINTENANCE HISTORY
            # ---------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS maintenance_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    request_id INT NOT NULL,
                    resolved_by_id INT NOT NULL,

                    resolution_details TEXT NOT NULL,

                    resolution_date
                        DATETIME DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (request_id)
                        REFERENCES maintenance_requests(id),

                    FOREIGN KEY (resolved_by_id)
                        REFERENCES users(id)
                )
            """)

            # ---------------------------------------------------------
            # ROLES
            # ---------------------------------------------------------

            cursor.execute("""
                INSERT INTO roles
                    (id, role_name)
                VALUES
                    (1, 'Admin'),
                    (2, 'Manager')
            """)

            # ---------------------------------------------------------
            # USERS
            # ---------------------------------------------------------

            admin_hash = generate_password_hash("admin123")
            manager_hash = generate_password_hash("manager123")

            cursor.execute("""
                INSERT INTO users
                    (id, username, password_hash, role_id)
                VALUES
                    (1, 'admin_user', %s, 1)
            """, (admin_hash,))

            cursor.execute("""
                INSERT INTO users
                    (id, username, password_hash, role_id)
                VALUES
                    (2, 'manager_user', %s, 2)
            """, (manager_hash,))

            # ---------------------------------------------------------
            # BUILDINGS
            # ---------------------------------------------------------

            buildings = [
                (1, "B001", "Main Hall", 500),
                (2, "B002", "Science Block", 300),
                (3, "B003", "Computing Building", 250),
                (4, "B004", "Library", 400)
            ]

            cursor.executemany("""
                INSERT INTO buildings
                    (id, building_code, building_name, capacity)
                VALUES
                    (%s, %s, %s, %s)
            """, buildings)

            # ---------------------------------------------------------
            # EQUIPMENT
            # ---------------------------------------------------------

            equipment = [
                (1, "Lecture Chairs", "Furniture", 150, "Working", 0),
                (1, "HD Projector", "Electronics", 2, "Faulty", 1),
                (1, "CCTV Camera", "Security", 4, "Working", 0),

                (2, "Lab Stools", "Furniture", 60, "Working", 0),
                (2, "Fume Hood", "Ventilation", 4, "Maintenance", 1),

                (3, "Desktop Computers", "Electronics", 80, "Working", 0),
                (3, "Network Switch", "IT", 2, "Working", 0),

                (4, "Reading Tables", "Furniture", 40, "Working", 0),
                (4, "CCTV Camera", "Security", 6, "Faulty", 2)
            ]

            cursor.executemany("""
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
                    (%s, %s, %s, %s, %s, %s)
            """, equipment)

            # ---------------------------------------------------------
            # SENSORS
            # ---------------------------------------------------------

            sensors = [
                (1, 1, "Temperature", "Online"),
                (2, 1, "Humidity", "Online"),
                (3, 1, "Air Quality", "Online"),

                (4, 2, "Temperature", "Online"),
                (5, 2, "Humidity", "Online"),
                (6, 2, "Air Quality", "Maintenance"),

                (7, 3, "Temperature", "Online"),
                (8, 3, "Humidity", "Online"),

                (9, 4, "Temperature", "Online"),
                (10, 4, "Air Quality", "Online")
            ]

            cursor.executemany("""
                INSERT INTO sensors
                    (
                        id,
                        building_id,
                        sensor_type,
                        status
                    )
                VALUES
                    (%s, %s, %s, %s)
            """, sensors)

            # ---------------------------------------------------------
            # SENSOR READINGS
            # ---------------------------------------------------------

            for sensor_id in range(1, 11):

                if sensor_id in [1, 4, 7, 9]:
                    base_value = 22.0

                elif sensor_id in [2, 5, 8]:
                    base_value = 45.0

                else:
                    base_value = 30.0

                for minutes_ago in [30, 20, 10, 0]:

                    value = base_value + random.uniform(-2, 2)

                    cursor.execute("""
                        INSERT INTO sensor_readings
                            (
                                sensor_id,
                                reading_value,
                                timestamp
                            )
                        VALUES
                            (%s, %s,
                             DATE_SUB(NOW(),
                             INTERVAL %s MINUTE))
                    """, (
                        sensor_id,
                        value,
                        minutes_ago
                    ))

            # ---------------------------------------------------------
            # MAINTENANCE REQUESTS
            # ---------------------------------------------------------

            cursor.execute("""
                INSERT INTO maintenance_requests
                    (
                        id,
                        requester_id,
                        building_id,
                        equipment_id,
                        details,
                        priority,
                        status
                    )
                VALUES
                    (
                        1,
                        1,
                        1,
                        2,
                        'Projector bulb blown in Main Hall',
                        'High',
                        'Pending'
                    )
            """)

            cursor.execute("""
                INSERT INTO maintenance_requests
                    (
                        id,
                        requester_id,
                        building_id,
                        equipment_id,
                        details,
                        priority,
                        status
                    )
                VALUES
                    (
                        2,
                        2,
                        4,
                        9,
                        'Two CCTV cameras blind in South Wing',
                        'Urgent',
                        'In Progress'
                    )
            """)

            cursor.execute("""
                INSERT INTO maintenance_requests
                    (
                        id,
                        requester_id,
                        building_id,
                        equipment_id,
                        details,
                        priority,
                        status
                    )
                VALUES
                    (
                        3,
                        2,
                        2,
                        5,
                        'Fume hood extraction fan squeaking',
                        'Normal',
                        'Resolved'
                    )
            """)

            # ---------------------------------------------------------
            # BUILDING REQUEST
            # ---------------------------------------------------------

            cursor.execute("""
                INSERT INTO building_requests
                    (
                        id,
                        requester_id,
                        building_id,
                        request_type,
                        details,
                        priority,
                        status
                    )
                VALUES
                    (
                        1,
                        2,
                        1,
                        'HVAC Calibration',
                        'Main Hall temperature fluctuating beyond standard range',
                        'Normal',
                        'Pending'
                    )
            """)

            # ---------------------------------------------------------
            # HISTORY
            # ---------------------------------------------------------

            cursor.execute("""
                INSERT INTO maintenance_history
                    (
                        request_id,
                        resolved_by_id,
                        resolution_details
                    )
                VALUES
                    (
                        3,
                        1,
                        'Replaced fan bearings and tested extraction rate.'
                    )
            """)

            connection.commit()

            print("Database successfully initialized and seeded.")
            print("")
            print("Admin login:")
            print("Username: admin_user")
            print("Password: admin123")
            print("")
            print("Manager login:")
            print("Username: manager_user")
            print("Password: manager123")

    finally:
        connection.close()


if __name__ == "__main__":
    init_database()