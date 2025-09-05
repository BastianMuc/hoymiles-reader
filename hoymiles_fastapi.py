from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib
import base64
import requests

class UnicornException(Exception):
    def __init__(self, message: str, code=400):
        self.message = message
        self.code = code

app = FastAPI()

@app.exception_handler(UnicornException)
async def unicorn_exception_handler(request: Request, exc: UnicornException):
    return JSONResponse(
        status_code=exc.code,
        content={"status":"1","message":f"{exc.message}"}
    )

@app.get("/")
def return_get_error():
    raise UnicornException(message="Only POST Requests with parameters username, password, sid allowed.")

@app.post("/", status_code=200)
async def application(request: Request):
    d = {}
    try:
        d = await request.json()
    except:
        raise UnicornException(message="Only POST Requests with parameters username, password, sid allowed.")

    if d.get("username") == None or not d["username"]:
        raise UnicornException(message="No username provided.", code=422)

    if d.get("password") == None or not d["password"]:
        raise UnicornException(message="No password provided.", code=422)

    if d.get("sid") == None:
        d["sid"] = ""

    user = d["username"]
    pwd = d["password"]
    sid = d["sid"]

    output = get_station_data(user, pwd, sid)

    return output

def get_station_data(user, pwd, sid):
    
    # Encode submitted password for submission to Hoymiles
    hash_md5 = hashlib.new('md5')
    hash_md5.update(pwd.encode('utf-8'))
    hash_object = hashlib.new('sha256')
    hash_object.update(pwd.encode('utf-8'))
    base64_bytes = base64.b64encode(hash_object.digest())
    base64_string = base64_bytes.decode('utf-8')
    pwd_string = hash_md5.hexdigest() + '.' + base64_string

    #Get Login Token
    url = "https://neapi.hoymiles.com/iam/pub/0/auth/login"
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    data = {
        "user_name": user,
        "password": pwd_string
    }
    response = requests.post(url, headers=headers, json=data)
    feedback = response.json()
    if feedback["status"] != "0":
        raise UnicornException(message="S-Miles Cloud Login failed. Please check username and password.", code=401)
    token = feedback["data"]["token"]

    # Helper function to return valid device IDs if none was provided.
    if not sid:
        url = "https://neapi.hoymiles.com/pvm/api/0/station/select_by_page"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
        data = {}
        sidsource = requests.post(url, headers=headers, json=data)
        sid_data = sidsource.json()
        sid_list = []
        if sid_data["status"] != "0":
            raise UnicornException(message="No station ID provided, unable to determine any from S-Miles Cloud.", code=422)
        else:
            sid_array = sid_data["data"]["list"]
            for item in sid_array:
                sid_list.append(item["id"])
            raise UnicornException(message="No station ID provided. Valid station IDs are: " + ', '.join(map(str, sid_list)) + ". Please enter one of them to your configuration.", code=422)

    # Obtain PV data
    url = "https://neapi.hoymiles.com/pvm-data/api/0/station/data/count_station_real_data"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    data = {
        "sid": sid
    }
    response = requests.post(url, headers=headers, json=data)
    pv_data = response.json()
    if pv_data["status"] != "0":
        raise UnicornException(message="Failed to obtain data. Please check if the station ID is correct.", code=422)

    current_day = pv_data["data"]["last_data_time"].split(" ", 1)[0]

    # Obtain daily history
    url = "https://neapi.hoymiles.com/pvm-report/api/0/station/report/select_power_by_station"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    data = {
        "sid_list": [
            sid
        ],
        "sid": sid,
        "start_date": current_day,
        "end_date": current_day,
        "page": 1,
        "page_size": 100
    }
    response = requests.post(url, headers=headers, json=data)
    daily_history = response.json()
    if daily_history["status"] != "0":
        raise UnicornException(message="Failed to obtain daily history. Please check if the station ID is correct.", code=422)

    pairings = []

    for item in daily_history["data"][0]["data_list"]:
        pairing_detail = []
        pairing_detail.append(item["date"])
        pairing_detail.append(int(round(float(item["pv_power"]))))
        pairings.append(pairing_detail)

    pv_data["chart"] = pairings
    return(pv_data)


