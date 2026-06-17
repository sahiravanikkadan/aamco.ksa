import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'taskmanager.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            pin_hash TEXT,
            profile_pic TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            assigned_to INTEGER,
            created_by INTEGER NOT NULL,
            group_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            priority TEXT NOT NULL DEFAULT 'medium',
            accepted_at TIMESTAMP,
            started_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (assigned_to) REFERENCES users(id),
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (group_id) REFERENCES task_groups(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS task_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#0d6efd',
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS delivery_persons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mobile TEXT,
            iqama_id TEXT,
            vehicle_no TEXT,
            vehicle_type TEXT,
            care_of TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS vehicle_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_note_number TEXT NOT NULL,
            description TEXT,
            customer_name TEXT NOT NULL,
            location_from TEXT,
            location_to TEXT,
            delivery_date DATE,
            delivery_person_id INTEGER,
            transportation_charge REAL DEFAULT 0,
            charge_paid INTEGER DEFAULT 0,
            paid_date DATE,
            paid_by TEXT,
            payment_method TEXT,
            narration TEXT,
            signed_note_status TEXT DEFAULT 'pending',
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (delivery_person_id) REFERENCES delivery_persons(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'info',
            is_read INTEGER NOT NULL DEFAULT 0,
            link TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT,
            attachment TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hr_employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            employee_name TEXT NOT NULL,
            employee_id TEXT,
            phone TEXT,
            designation TEXT,
            joining_date DATE NOT NULL,
            basic_salary REAL NOT NULL DEFAULT 0,
            housing_allowance REAL NOT NULL DEFAULT 0,
            transport_allowance REAL NOT NULL DEFAULT 0,
            other_allowance REAL NOT NULL DEFAULT 0,
            ticket_amount REAL NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS hr_leaves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            leave_start_date DATE NOT NULL,
            leave_end_date DATE NOT NULL,
            rejoin_date DATE,
            leave_type TEXT NOT NULL DEFAULT 'annual',
            vacation_days INTEGER NOT NULL DEFAULT 0,
            working_days INTEGER NOT NULL DEFAULT 0,
            daily_salary REAL NOT NULL DEFAULT 0,
            leave_salary REAL NOT NULL DEFAULT 0,
            ticket_included INTEGER NOT NULL DEFAULT 0,
            ticket_amount REAL NOT NULL DEFAULT 0,
            total_amount REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            notes TEXT,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES hr_employees(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_name TEXT NOT NULL,
            plate_number TEXT NOT NULL,
            vehicle_type TEXT,
            driver_name TEXT,
            driver_id INTEGER,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (driver_id) REFERENCES delivery_persons(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS vehicle_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            document_type TEXT NOT NULL,
            document_number TEXT,
            issue_date DATE,
            expiry_date DATE NOT NULL,
            reminder_days INTEGER NOT NULL DEFAULT 30,
            attachment TEXT,
            notes TEXT,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vehicle_id) REFERENCES vehicles(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
    ''')

    # Add phone column if missing (migration)
    try:
        conn.execute("SELECT phone FROM users LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE users ADD COLUMN phone TEXT")

    # Add group_id column if missing (migration)
    try:
        conn.execute("SELECT group_id FROM tasks LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE tasks ADD COLUMN group_id INTEGER REFERENCES task_groups(id) ON DELETE SET NULL")

    # Add rejoin_date and vacation_days to hr_leaves if missing (migration)
    try:
        conn.execute("SELECT rejoin_date FROM hr_leaves LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE hr_leaves ADD COLUMN rejoin_date DATE")
    try:
        conn.execute("SELECT vacation_days FROM hr_leaves LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE hr_leaves ADD COLUMN vacation_days INTEGER NOT NULL DEFAULT 0")

    # Add amount_paid column for partial payments (migration)
    try:
        conn.execute("SELECT amount_paid FROM deliveries LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE deliveries ADD COLUMN amount_paid REAL DEFAULT 0")

    # Add vehicle_type to delivery_persons (migration)
    try:
        conn.execute("SELECT vehicle_type FROM delivery_persons LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE delivery_persons ADD COLUMN vehicle_type TEXT")

    # Add care_of to delivery_persons (migration)
    try:
        conn.execute("SELECT care_of FROM delivery_persons LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE delivery_persons ADD COLUMN care_of TEXT")

    # Add location_from, location_to to deliveries (migration)
    try:
        conn.execute("SELECT location_from FROM deliveries LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE deliveries ADD COLUMN location_from TEXT")
    try:
        conn.execute("SELECT location_to FROM deliveries LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE deliveries ADD COLUMN location_to TEXT")

    # Add received_by and note_copy_type to deliveries (migration)
    try:
        conn.execute("SELECT received_by FROM deliveries LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE deliveries ADD COLUMN received_by TEXT")
    try:
        conn.execute("SELECT note_copy_type FROM deliveries LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE deliveries ADD COLUMN note_copy_type TEXT")

    # Create delivery_payments table for payment history
    conn.execute('''
        CREATE TABLE IF NOT EXISTS delivery_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            paid_by_employee TEXT,
            paid_date DATE,
            notes TEXT,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (delivery_id) REFERENCES deliveries(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # Auto-populate customers from existing deliveries
    conn.execute("INSERT OR IGNORE INTO customers (name) SELECT DISTINCT customer_name FROM deliveries WHERE customer_name != ''")

    # Default vehicle types
    default_vtypes = ['Sedan', 'SUV', 'Pickup', 'Van', 'Truck', 'Motorcycle', 'Bus', 'Trailer']
    for vt in default_vtypes:
        conn.execute('INSERT OR IGNORE INTO vehicle_types (name) VALUES (?)', (vt,))

    # Add leave payment columns to hr_leaves (migration)
    for col, coltype in [('amount_paid', 'REAL DEFAULT 0'), ('payment_date', 'DATE'),
                         ('payment_reference', 'TEXT'), ('payment_method', 'TEXT'),
                         ('paid_by', 'TEXT'), ('calc_mode', "TEXT DEFAULT 'auto'")]:
        try:
            conn.execute(f"SELECT {col} FROM hr_leaves LIMIT 1")
        except Exception:
            conn.execute(f"ALTER TABLE hr_leaves ADD COLUMN {col} {coltype}")

    # Ensure settings table has defaults
    defaults = {
        'print_paper_size': 'A4',
        'print_orientation': 'portrait',
        'print_company_name': 'AIRSCENT ARABIA MANUFACTURING CO.',
        'print_show_logo': '1',
        'auto_backup': '1',
        'backup_interval_minutes': '30',
        'pin_on_add': '0',
        'pin_on_edit': '0',
        'pin_on_delete': '0',
        'pin_on_tasks': '0',
        'pin_on_deliveries': '0',
        'pin_on_hr': '0',
        'pin_on_vehicles': '0',
        'leave_salary_divisor': '365',
        'leave_include_basic': '1',
        'leave_include_housing': '1',
        'leave_include_transport': '1',
        'leave_include_other': '1',
        'leave_include_ticket': '1',
        'leave_calc_mode': 'auto',
    }
    for k, v in defaults.items():
        conn.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    conn.commit()
    conn.close()
