#!python
import logging
from contextlib import asynccontextmanager
from typing import Union, List
from fastapi import FastAPI, HTTPException
from apscheduler.schedulers.background import BackgroundScheduler
from netmiko import ConnectHandler
from pydantic import BaseModel


class Device(BaseModel):
    hostname: str
    device_type: str = "cisco_ios"
    username: str
    password: str


class SingleCommandRequest(BaseModel):
    hostname: str
    command: str
    command_type: str = "standard"


class MultiCommandRequest(BaseModel):
    hostname: str
    commands: List[str]
    command_type: str = "standard"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    startup_tasks(app)
    yield
    # Shutdown tasks
    shutdown_tasks(app)


app = FastAPI(title="sshrest", lifespan=lifespan)
devices = {}
scheduler = BackgroundScheduler()
logger = logging.getLogger('uvicorn.error')


def startup_tasks(app: FastAPI):
    scheduler.start()
    logger.info("Scheduler has started.")
    scheduler.add_job(interval_tasks, 'interval', seconds=10)


def shutdown_tasks(app: FastAPI):
    scheduler.shutdown()
    logger.info("Scheduler has stopped.")


def interval_tasks():
    logger.debug("Recurring interval tasks have started.")

    for device_ip in devices.keys():
        device = devices[device_ip]
        if not device.is_alive():
            try:
                logger.warning(f"{device_ip} is disconnected. Attempting reconnect...")
                device.establish_connection()
                if device.is_alive():
                    logger.info(f"{device_ip} is now connected.")
                else:
                    logger.error(f"{device_ip} failed to reconnect, will retry.")
            except:
                logger.error(f"{device_ip} failed to reconnect, will retry.")


@app.get("/")
def read_root():
    return {"status": "success"}


@app.get("/devices")
def list_devices():
    return {'devices': list(devices.keys())}


@app.post("/remove", status_code=204)
def remove_device(hostname: str):
    if hostname not in devices.keys():
        raise HTTPException(status_code=404, detail="Device not found")

    devices.pop(hostname)


@app.post("/add", status_code=201)
def add_device(device: Device):
    if device.hostname in devices.keys():
        raise HTTPException(status_code=400, detail="Device already added")

    try:
        devices[device.hostname] = ConnectHandler(
            device_type=device.device_type,
            host=device.hostname,
            username=device.username,
            password=device.password,
            auto_connect=False,
            conn_timeout=5000,
            keepalive=5
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=error.__str__())


@app.post("/command")
def run_command(request: SingleCommandRequest):
    if request.hostname not in devices.keys():
        raise HTTPException(status_code=404, detail="Device not found")

    if not devices[request.hostname].is_alive():
        raise HTTPException(status_code=503, detail="Device currently unreachable")

    output = ""
    if request.command_type == "standard" or request.command_type == "enabled":
        if request.command_type == "enabled":
            devices[request.hostname].enable()
        output = devices[request.hostname].send_command(request.command)
    elif request.command_type == "config":
        commands = [request.command]
        output = devices[request.hostname].send_config_set(commands)
    else:
        raise HTTPException(status_code=400, detail="Unsupported command type")

    return {"output": output}


@app.post("/batch_command")
def run_command_batch(request: MultiCommandRequest):
    if request.hostname not in devices.keys():
        raise HTTPException(status_code=404, detail="Device not found")

    if not devices[request.hostname].is_alive():
        raise HTTPException(status_code=503, detail="Device currently unreachable")

    output = ""
    if request.command_type == "standard" or request.command_type == "enabled":
        if request.command_type == "enabled":
            devices[request.hostname].enable()
        for line in request.commands:
            output = output + devices[request.hostname].send_command(line)
    elif request.command_type == "config":
        output = devices[request.hostname].send_config_set(request.commands)

    return {"output": output}
