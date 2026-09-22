import os
import random

import pymysql
import pymysql.cursors

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash


load_dotenv()


# ============================================================
# DATABASE INITIALISATION
# ============================================================

def init_database():

    db_name = os.getenv(
        "DB_NAME",
        "defaultdb"
    )

    ca_path = os.getenv(
        "DB_SSL_CA",
        r"C:\Users\ASUS\smart_building_system\ca.pem"
    )

    connection = pymysql.connect(
        host=os.getenv(
            "DB_HOST",
            "localhost"
        ),
        port=int(
            os.getenv(
                "DB_PORT",
                "3306"
            )
        ),
        user=os.getenv(
            "DB_USER",
            "root"
        ),
        password=os.getenv(
            "DB_PASSWORD",
            ""
        ),
        cursorclass=pymysql.cursors.DictCursor,

        # Aiven MySQL requires SSL.
        ssl={
            "ca": ca_path
        }
    )

    try:

        with connection.cursor() as cursor:

            # ====================================================
            # DATABASE
            # ====================================================

            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}`"
            )

            cursor.execute(
                f"USE `{db_name}`"
            )


            # ====================================================
            # ROLES
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS roles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    role_name VARCHAR(50) NOT NULL UNIQUE
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # USERS
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    username VARCHAR(100)
                        NOT NULL UNIQUE,

                    password_hash VARCHAR(255)
                        NOT NULL,

                    role_id INT,

                    status VARCHAR(20)
                        DEFAULT 'active',

                    FOREIGN KEY (role_id)
                        REFERENCES roles(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # BUILDINGS
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS buildings (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    building_code VARCHAR(10)
                        NOT NULL,

                    building_name VARCHAR(100)
                        NOT NULL,

                    capacity INT
                        NOT NULL
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # EQUIPMENT
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS equipment (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    building_id INT,

                    equipment_name VARCHAR(100)
                        NOT NULL,

                    equipment_type VARCHAR(100),

                    quantity INT
                        DEFAULT 1,

                    status ENUM(
                        'Working',
                        'Maintenance',
                        'Faulty'
                    )
                    DEFAULT 'Working',

                    faulty_count INT
                        DEFAULT 0,

                    created_at DATETIME
                        DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # SENSORS
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sensors (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    building_id INT,

                    sensor_type ENUM(
                        'Temperature',
                        'Humidity',
                        'Air Quality'
                    )
                    NOT NULL,

                    status ENUM(
                        'Online',
                        'Offline',
                        'Maintenance'
                    )
                    DEFAULT 'Online',

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # SENSOR READINGS
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sensor_readings (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    sensor_id INT,

                    reading_value FLOAT,

                    timestamp DATETIME
                        DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (sensor_id)
                        REFERENCES sensors(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # MAINTENANCE REQUESTS
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS maintenance_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    requester_id INT,

                    building_id INT,

                    equipment_id INT NULL,

                    details TEXT,

                    priority ENUM(
                        'Normal',
                        'High',
                        'Urgent'
                    )
                    DEFAULT 'Normal',

                    status ENUM(
                        'Pending',
                        'In Progress',
                        'Resolved'
                    )
                    DEFAULT 'Pending',

                    created_at DATETIME
                        DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (requester_id)
                        REFERENCES users(id),

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id),

                    FOREIGN KEY (equipment_id)
                        REFERENCES equipment(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # BUILDING REQUESTS
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS building_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    requester_id INT,

                    building_id INT,

                    request_type VARCHAR(100)
                        NOT NULL,

                    details TEXT,

                    priority ENUM(
                        'Normal',
                        'High',
                        'Urgent'
                    )
                    DEFAULT 'Normal',

                    status ENUM(
                        'Pending',
                        'In Progress',
                        'Resolved'
                    )
                    DEFAULT 'Pending',

                    created_at DATETIME
                        DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (requester_id)
                        REFERENCES users(id),

                    FOREIGN KEY (building_id)
                        REFERENCES buildings(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # MAINTENANCE HISTORY
            #
            # Supports both:
            #
            # Maintenance request:
            # request_id = ID
            # building_request_id = NULL
            #
            # Building request:
            # request_id = NULL
            # building_request_id = ID
            # ====================================================

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS maintenance_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,

                    request_id INT NULL,

                    building_request_id INT NULL,

                    resolved_by_id INT NOT NULL,

                    resolution_details TEXT,

                    resolution_date DATETIME
                        DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (request_id)
                        REFERENCES maintenance_requests(id),

                    FOREIGN KEY (building_request_id)
                        REFERENCES building_requests(id),

                    FOREIGN KEY (resolved_by_id)
                        REFERENCES users(id)
                ) ENGINE=InnoDB
                """
            )


            # ====================================================
            # ROLES
            # ====================================================

            cursor.execute(
                """
                INSERT IGNORE INTO roles
                    (
                        id,
                        role_name
                    )
                VALUES
                    (
                        1,
                        'Manager'
                    ),
                    (
                        2,
                        'User'
                    )
                """
            )


            # ====================================================
            # USERS
            # ====================================================

            manager_hash = generate_password_hash(
    "manager123"
)

user_hash = generate_password_hash(
    "user123"
)

            cursor.execute(
                """
                INSERT IGNORE INTO users
                    (
                        id,
                        username,
                        password_hash,
                        role_id,
                        status
                    )
                VALUES
                    (
                        1,
                        'manager_account',
                        %s,
                        1,
                        'active'
                    )
                """,
                (manager_hash,)
            )

            cursor.execute(
                """
                INSERT IGNORE INTO users
                    (
                        id,
                        username,
                        password_hash,
                        role_id,
                        status
                    )
                VALUES
                    (
                        2,
                        'user_account',
                        %s,
                        2,
                        'active'
                    )
                """,
                (user_hash,)
            )


            # ====================================================
            # BUILDINGS
            # ====================================================

            buildings_data = [

                (
                    1,
                    "B001",
                    "Main Hall",
                    500
                ),

                (
                    2,
                    "B002",
                    "Science",
                    300
                ),

                (
                    3,
                    "B003",
                    "Computing",
                    250
                ),

                (
                    4,
                    "B004",
                    "Library",
                    400
                )

            ]

            cursor.executemany(
                """
                INSERT IGNORE INTO buildings
                    (
                        id,
                        building_code,
                        building_name,
                        capacity
                    )
                VALUES
                    (
                        %s,
                        %s,
                        %s,
                        %s
                    )
                """,
                buildings_data
            )


            # ====================================================
            # EQUIPMENT
            # ====================================================

            equipment_data = [

                (
                    1,
                    "Lecture Chairs",
                    "Furniture",
                    150,
                    "Working",
                    0
                ),

                (
                    1,
                    "HD Projector",
                    "Electronics",
                    2,
                    "Faulty",
                    1
                ),

                (
                    1,
                    "CCTV Camera",
                    "Security",
                    4,
                    "Working",
                    0
                ),

                (
                    2,
                    "Lab Stools",
                    "Furniture",
                    60,
                    "Working",
                    0
                ),

                (
                    2,
                    "Fume Hood",
                    "Ventilation",
                    4,
                    "Maintenance",
                    1
                ),

                (
                    3,
                    "Desktop Computers",
                    "Electronics",
                    80,
                    "Working",
                    0
                ),

                (
                    3,
                    "Network Switch",
                    "IT",
                    2,
                    "Working",
                    0
                ),

                (
                    4,
                    "Reading Tables",
                    "Furniture",
                    40,
                    "Working",
                    0
                ),

                (
                    4,
                    "CCTV Camera",
                    "Security",
                    6,
                    "Faulty",
                    2
                )

            ]

            for equipment in equipment_data:

                cursor.execute(
                    """
                    SELECT id
                    FROM equipment
                    WHERE building_id = %s
                      AND equipment_name = %s
                    LIMIT 1
                    """,
                    (
                        equipment[0],
                        equipment[1]
                    )
                )

                existing = cursor.fetchone()

                if not existing:

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
                                %s,
                                %s
                            )
                        """,
                        equipment
                    )


            # ====================================================
            # SENSORS
            # ====================================================

            sensors_data = [

                (
                    1,
                    1,
                    "Temperature",
                    "Online"
                ),

                (
                    2,
                    1,
                    "Humidity",
                    "Online"
                ),

                (
                    3,
                    1,
                    "Air Quality",
                    "Online"
                ),

                (
                    4,
                    2,
                    "Temperature",
                    "Online"
                ),

                (
                    5,
                    2,
                    "Humidity",
                    "Online"
                ),

                (
                    6,
                    2,
                    "Air Quality",
                    "Maintenance"
                ),

                (
                    7,
                    3,
                    "Temperature",
                    "Online"
                ),

                (
                    8,
                    3,
                    "Humidity",
                    "Online"
                ),

                (
                    9,
                    4,
                    "Temperature",
                    "Online"
                ),

                (
                    10,
                    4,
                    "Air Quality",
                    "Online"
                )

            ]

            for sensor in sensors_data:

                cursor.execute(
                    """
                    INSERT IGNORE INTO sensors
                        (
                            id,
                            building_id,
                            sensor_type,
                            status
                        )
                    VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s
                        )
                    """,
                    sensor
                )


            # ====================================================
            # SENSOR READINGS
            # ====================================================

            sensor_values = {

                1: 22.0,
                2: 45.0,
                3: 30.0,
                4: 23.0,
                5: 50.0,
                6: 35.0,
                7: 24.0,
                8: 48.0,
                9: 21.0,
                10: 40.0

            }

            for sensor_id, base_value in sensor_values.items():

                cursor.execute(
                    """
                    SELECT id
                    FROM sensor_readings
                    WHERE sensor_id = %s
                    LIMIT 1
                    """,
                    (sensor_id,)
                )

                existing_reading = cursor.fetchone()

                if not existing_reading:

                    for minutes_ago in [
                        180,
                        120,
                        60,
                        30,
                        0
                    ]:

                        value = (
                            base_value
                            + random.uniform(
                                -2.0,
                                2.0
                            )
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
                                sensor_id,
                                value,
                                minutes_ago
                            )
                        )


            # ====================================================
            # MAINTENANCE EXAMPLES
            # ====================================================

            maintenance_data = [

                (
                    1,
                    1,
                    1,
                    2,
                    "Projector bulb blown in Main Hall",
                    "High",
                    "Pending"
                ),

                (
                    2,
                    2,
                    4,
                    9,
                    "Two CCTV cameras blind in South Wing",
                    "Urgent",
                    "In Progress"
                ),

                (
                    3,
                    2,
                    2,
                    5,
                    "Fume hood extraction fan squeaking",
                    "Normal",
                    "Resolved"
                )

            ]

            for maintenance in maintenance_data:

                cursor.execute(
                    """
                    INSERT IGNORE INTO maintenance_requests
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
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s
                        )
                    """,
                    maintenance
                )


            # ====================================================
            # BUILDING REQUEST
            # ====================================================

            cursor.execute(
                """
                INSERT IGNORE INTO building_requests
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
                """
            )


            # ====================================================
            # HISTORY
            #
            # This history record is for maintenance request #3.
            #
            # request_id = 3
            # building_request_id = NULL
            # ====================================================

            cursor.execute(
                """
                INSERT IGNORE INTO maintenance_history
                    (
                        request_id,
                        building_request_id,
                        resolved_by_id,
                        resolution_details
                    )
                VALUES
                    (
                        3,
                        NULL,
                        1,
                        'Replaced fan bearings and tested extraction rate.'
                    )
                """
            )


        # ========================================================
        # COMMIT
        # ========================================================

        connection.commit()

        print()
        print(
            "Database successfully initialized on Aiven MySQL."
        )
        print()

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    init_database()

    print()
print("Manager login:")
print("Username: manager_account")
print("Password: manager123")
print()

print("User login:")
print("Username: user_account")
print("Password: user123")