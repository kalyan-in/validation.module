import re
from typing import Any, Dict, List, Union
from datetime import datetime

#User & Authentication Validators

def validate_email(value: str) -> bool:
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", value) is not None

def validate_password_strength(value: str) -> bool:
    # At least one lowercase, one uppercase, one digit, one special char, min 8 chars
    return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,}$", value) is not None

def validate_username(value: str) -> bool:
    return re.match(r"^[A-Za-z0-9_]{3,30}$", value) is not None

def validate_phone_number(value: str, country_code: str = "IN") -> bool:
    # Basic 10-digit number
    return re.match(r"^\d{10}$", value) is not None

def validate_country_code(value: str) -> bool:
    return re.match(r"^[A-Z]{2}$", value) is not None

def validate_gender(value: str) -> bool:
    return value in ["M", "F", "Other"]

def validate_dob_range(value: str, min_age: int, max_age: int) -> bool:
    try:
        dob = datetime.strptime(value, "%Y-%m-%d")
        today = datetime.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return min_age <= age <= max_age
    except Exception:
        return False

def validate_otp(value: str) -> bool:
    return re.match(r"^\d{4,6}$", value) is not None

def validate_auth_token(value: str) -> bool:
    return isinstance(value, str) and len(value) >= 10

# Financial & Payment Validators 

def validate_credit_card(value: str) -> bool:
    return re.match(r"^\d{16}$", value) is not None

def validate_cvv(value: str) -> bool:
    return re.match(r"^\d{3,4}$", value) is not None

def validate_expiry_date(value: str) -> bool:
    try:
        exp = datetime.strptime(value, "%m/%y")
        return exp > datetime.now()
    except Exception:
        return False

def validate_payment_status(value: str) -> bool:
    return value in ["Pending", "Completed"]

def validate_transaction_id(value: str) -> bool:
    return re.match(r"^[A-Z0-9]{10,}$", value) is not None

def validate_invoice_number(value: str) -> bool:
    return re.match(r"^[A-Z0-9\-]{5,}$", value) is not None

def validate_gstin_number(value: str) -> bool:
    return re.match(r"^\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}$", value) is not None

def validate_pan_number(value: str) -> bool:
    return re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", value) is not None

def validate_ifsc_code(value: str) -> bool:
    return re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", value) is not None

def validate_upi_id(value: str) -> bool:
    return re.match(r"^[\w.-]+@[\w]+$", value) is not None

#  Address & Location Validators

def validate_zip_code(value: str, country: str = "IN") -> bool:
    return re.match(r"^\d{5,6}$", value) is not None

def validate_city_name(value: str) -> bool:
    return value.isalpha()

def validate_state_name(value: str) -> bool:
    return value.isalpha()

def validate_latitude(value: float) -> bool:
    return -90 <= value <= 90

def validate_longitude(value: float) -> bool:
    return -180 <= value <= 180

def validate_ip_address(value: str) -> bool:
    return re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value) is not None

def validate_country_name(value: str) -> bool:
    return value.isalpha()

# Document & File Validators 

def validate_aadhar_number(value: str) -> bool:
    return re.match(r"^\d{12}$", value) is not None

def validate_voter_id(value: str) -> bool:
    return re.match(r"^[A-Z]{3}[0-9]{7}$", value) is not None

def validate_passport_number(value: str) -> bool:
    return re.match(r"^[A-Z]{1}-?\d{7}$", value) is not None

def validate_driving_license(value: str) -> bool:
    return re.match(r"^[A-Z]{2}\d{13}$", value) is not None

def validate_document_type(value: str) -> bool:
    return value.upper() in ['PDF', 'JPG']

def validate_file_size(file: Any, max_size_mb: int) -> bool:
    try:
        return file.size <= max_size_mb * 1024 * 1024
    except Exception:
        return False

def validate_image_format(file_name: str) -> bool:
    return file_name.lower().endswith(('.png', '.jpg', '.jpeg'))

# Security & Token Validators 

def validate_sql_injection(value: str) -> bool:
    keywords = ['--', ';', '/*', '*/', '@@', '@', 'char', 'nchar', 'varchar', 'nvarchar']
    return not any(keyword in value.lower() for keyword in keywords)

def validate_xss(value: str) -> bool:
    return not bool(re.search(r'<script.*?>.*?</script>', value, re.IGNORECASE))

def validate_csrf_token(value: str) -> bool:
    return re.match(r'^[a-zA-Z0-9-_]{32,}$', value) is not None

def validate_jwt_token(value: str) -> bool:
    return len(value.split('.')) == 3

def validate_api_key(value: str) -> bool:
    return re.match(r'^[A-Z0-9]{20,40}$', value) is not None

def validate_oauth_token(value: str) -> bool:
    return isinstance(value, str) and len(value) >= 20

# Object & Array Validators

def validate_object_keys(obj: dict, required_keys: list) -> bool:
    return all(k in obj for k in required_keys)

def validate_array_size(arr: list, min_size: int, max_size: int) -> bool:
    return min_size <= len(arr) <= max_size

def validate_unique_elements(arr: list) -> bool:
    return len(arr) == len(set(arr))

def validate_nested_object(obj: dict, schema: dict) -> bool:
    return validate(schema, obj)["status"]

def validate_array_of_objects(arr: list, schema: dict) -> bool:
    return all(validate(schema, item)["status"] for item in arr)

#  Additional Validators 

def validate_schedule(value: str) -> bool:
    # e.g., "Mon-Fri 9AM-5PM"
    return re.match(r"^[A-Za-z]{3}-[A-Za-z]{3}\s\d{1,2}[APMapm]{2}-\d{1,2}[APMapm]{2}$", value) is not None

def validate_employee_code(value: str) -> bool:
    return re.match(r"^EMP\d{4,10}$", value) is not None

def validate_regex(value: str, pattern: str) -> bool:
    return re.match(pattern, value) is not None

def validate_foreign_key(value: Any) -> bool:
    # Example: must be a string starting with "id_"
    return isinstance(value, str) and value.startswith("id_")

def validate_list_of_strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)

def validate_uuid(value: str) -> bool:
    return re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", value) is not None

# JSON Schema Validation Engine 

def validate(schema: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    errors = []

    if schema.get("type") != "object" or "properties" not in schema:
        return {"errors": ["Schema must define an object with properties"], "status": False}

    required_fields = schema.get("required", [])
    properties = schema["properties"]

    for field in required_fields:
        if field not in data:
            errors.append(f"Field '{field}' is required")

    for field, rules in properties.items():
        value = data.get(field)
        field_type = rules.get("type")

        if value is not None:
            if field_type == "string":
                if not isinstance(value, str):
                    errors.append(f"Field '{field}' must be a string")
                if "minLength" in rules and len(value) < rules["minLength"]:
                    errors.append(f"Field '{field}' must be at least {rules['minLength']} characters")
                if "pattern" in rules and not re.match(rules["pattern"], value):
                    errors.append(f"Field '{field}' does not match the pattern")
                if rules.get("format") == "email" and not validate_email(value):
                    errors.append(f"Field '{field}' must be a valid email")

            elif field_type == "number":
                if not isinstance(value, (int, float)):
                    errors.append(f"Field '{field}' must be a number")
                if "minimum" in rules and value < rules["minimum"]:
                    errors.append(f"Field '{field}' must be >= {rules['minimum']}")
                if "maximum" in rules and value > rules["maximum"]:
                    errors.append(f"Field '{field}' must be <= {rules['maximum']}")

            elif field_type == "boolean":
                if not isinstance(value, bool):
                    errors.append(f"Field '{field}' must be a boolean")

            elif field_type == "object":
                nested_result = validate(rules, value)
                if not nested_result["status"]:
                    errors.append(f"Field '{field}' object validation failed: {nested_result['errors']}")

            elif field_type == "array":
                if not isinstance(value, list):
                    errors.append(f"Field '{field}' must be an array")
                elif "items" in rules:
                    item_schema = rules["items"]
                    for i, item in enumerate(value):
                        if item_schema.get("type") == "object":
                            result = validate(item_schema, item)
                            if not result["status"]:
                                errors.append(f"Item {i} in '{field}' failed: {result['errors']}")
                        else:
                            # For non-object items, perform basic type check (e.g., string)
                            expected = item_schema.get("type")
                            if expected == "string" and not isinstance(item, str):
                                errors.append(f"Item {i} in '{field}' must be a string")
                            # Additional type checks can be added here

            if "enum" in rules and value not in rules["enum"]:
                errors.append(f"Field '{field}' must be one of {rules['enum']}")

    return {
        "errors": errors,
        "status": len(errors) == 0
    }

# End of Validation Library 

if __name__ == "__main__":
    # Example JSON Schema with Type Validation
    example_schema = {
        "type": "object",
        "properties": {
            "email": { "type": "string", "format": "email" },
            "password": { "type": "string", "minLength": 8 },
            "phone": { "type": "string", "pattern": "^\\d{10}$" },
            "age": { "type": "number", "minimum": 18, "maximum": 65 },
            "gender": { "type": "string", "enum": ["M", "F", "Other"] },
            "address": {
                "type": "object",
                "properties": {
                    "city": { "type": "string" },
                    "state": { "type": "string" },
                    "zip": { "type": "string", "pattern": "^\\d{5}$" }
                },
                "required": ["city", "state", "zip"]
            }
        },
        "required": ["email", "password", "phone", "age"]
    }

    # Example data to validate
    example_data = {
        "email": "john@example.com",
        "password": "Secure@123",
        "phone": "1234567890",
        "age": 25,
        "gender": "M",
        "address": {
            "city": "New York",
            "state": "NY",
            "zip": "10001"
        }
    }

    result = validate(example_schema, example_data)
    print(result)
