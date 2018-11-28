# For ContentProvider Vul.  Hook 2 methods, including openFile() + open() & query()
# 框架，输入包名、类名，自动找到对应的方法，生成进行hook的js代码。完成contentprovider漏洞的部分。
# option:
# 0 contentProvider
# 1 AppClone
# 2 WebView Url:Scheme
# alipays://?aluTargetLoginId=file:///data/data/com.eg.android.AlipayGphone/exp2.html
import frida, sys, json
from termcolor import colored

def build_script_getOverloadNum(classname,methodname):  # get the number of overloads
    jscode = '''
        Java.perform(function() {
            var Handler = Java.use('%(className)s');

            var overload_count = Handler['%(methodName)s'].overloads.length;

            var payload = {
                "type": "overloadNum",
                "num": overload_count
            };
            send(JSON.stringify(payload));
    })

    '''%{"className":classname,"methodName":methodname}
    return jscode

def build_script_trigger():
    testCaseCodes = test_case_generator('/Users/eacials/proj08/vul/AppClone/testCaseAppClone')

    jscode = '''
        var triggerTestCaseCount = 0;
        %s
        Java.perform(function(){
            var Uri = Java.use('android.net.Uri');
            var Intent = Java.use('android.content.Intent');
            Intent.$init.overload('java.lang.String','android.net.Uri').implementation = function(a0,a1){
                console.log("trigger hooked!!");
                var newUri = Uri.parse(testCases[triggerTestCaseCount]);
                triggerTestCaseCount+=1;
                a1 = newUri;
                var payload = {
                    "type": "triggerfilename",
                    "filename": "exp2"
                };
                send(JSON.stringify(payload));
                console.log("newUri:" + a1);
                return this.$init(a0,a1);
            }
        })
    '''% (testCaseCodes)
    return jscode

def build_script_method_openFile(packagename, classname):
    global overloadNum
    generated_codes = ""
    jscode = build_script_getOverloadNum(classname,"openFile")
    begin_instrumentation(packagename,jscode)
    if overloadNum == 0:
        print(colored('[ERROR]:Can\'t find method \'' + openFile + '\'', "red"))
    else:
        generated_codes = "var count = 0;"
        hook_code = '''
            OpenFile_QueryHandler.openFile.overloads[i].implementation = function(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15){
                console.log("ori:" + arguments[0]);
                arguments[0] = UriClass.parse(testCases[count]);
                console.log("now:" + arguments[0]);
                var items = testCases[count].split("2F");
                filename = items[items.length-1];
                count+=1;
                if(count >= testCases.length){
                    count = testCases.length-1;
                    var payload = {
                        "type": "Warning",
                        "cont": "TestCases has run out!"
                    }
                    send(JSON.stringify(payload));
                }
                return this.openFile.overloads[i].apply(this, arguments);
            }
        '''
        for index in range(0,overloadNum):
            f_hook_code = hook_code.replace("overloads[i]", "overloads[" + str(index) +"]")
            generated_codes+=f_hook_code
    return generated_codes

def build_script_method_open(packagename, classname):
    global overloadNum
    generated_codes = ""
    jscode = build_script_getOverloadNum(classname,"open")
    begin_instrumentation(packagename,jscode)
    if overloadNum == 0:
        print(colored('[ERROR]:Can\'t find method \'' + "open" + '\'', "red"))
    else:
        hook_code = '''
            OpenHandler.open.overloads[i].implementation = function(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15){
                console.log("opa:" + arguments[0]);
                var items = arguments[0].toString().split("/");
                var filename1 = items[items.length-1];
                var result = this.open.overloads[i].apply(this, arguments);
                console.log(filename);
                console.log(filename1);
                if(result != null && filename1 == filename){
                    console.log("vul detected!");
                    var payload = {
                        "type": "Detected",
                        "cont": "Find ContentProvider Vulnerability(Arbitrary access)."
                    }
                    send(JSON.stringify(payload));
                }
                return result;
            }
        '''
        for index in range(0,overloadNum):
            f_hook_code = hook_code.replace("overloads[i]", "overloads[" + str(index) +"]")
            generated_codes+=f_hook_code
    return generated_codes

def build_script_method_query(packagename, classname):
    global overloadNum
    generated_codes = ""
    jscode = build_script_getOverloadNum(classname,"query")
    begin_instrumentation(packagename,jscode)
    if overloadNum == 0:
        print(colored('[ERROR]:Can\'t find method \'' + "query" + '\'', "red"))
    else:
        hook_code = '''
            OpenFile_QueryHandler.query.overloads[i].implementation = function(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15){
                var result = this.query.overloads[i].apply(this, arguments);
                if(result != null){
                    var payload = {
                        "type": "Detected",
                        "cont": "Find ContentProvider Vulnerability(SQL injection)."
                    }
                    send(JSON.stringify(payload));
                }
                return result;
            }
        '''
        for index in range(0,overloadNum):
            f_hook_code = hook_code.replace("overloads[i]", "overloads[" + str(index) +"]")
            generated_codes+=f_hook_code
    return generated_codes

# def build_script_method_loadUrl(packagename, classname):
#     global overloadNum
#     generated_codes = ""
#     jscode = build_script_getOverloadNum(classname,"loadUrl")
#     begin_instrumentation(packagename,jscode)
#     if overloadNum == 0:
#         print(colored('[ERROR]:Can\'t find method \'' + "loadUrl" + '\'', "red"))
#     else:
#         hook_code = '''
#             WebView_Handler.loadUrl.overloads[i].implementation = function(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15){
#                 input_url = arguments[0];
#                 var triggerfile;
#                 console.log("input:" + input_url);
#                 var op = recv('triggername',function onMessage(triggerMessage){
#                     triggerfile = triggerMessage[filename];
#                     console.log("recv!!!!")
#                 });
#                 op.wait();
#                 console.log("newinput:" + triggerfile);
#                 var result = this.loadUrl.overloads[i].apply(this, arguments);
#                 return result;
#             }
#         '''
#         for index in range(0,overloadNum):
#             f_hook_code = hook_code.replace("overloads[i]", "overloads[" + str(index) +"]")
#             generated_codes+=f_hook_code
#     return generated_codes

# def build_script_method_wbClient_onPagefinished():
#     hook_code = '''
#         //wbClient_Handler.onPageFinished.overload('android.webkit.WebView', 'java.lang.String').implementation = function(a1,a2){
#         wbClient_Handler.onPageFinished.overloads[0].implementation = function(a0,a1,a2,a3){
#             console.log(a1);
#             if(input_url == a1){
#                 var payload = {
#                     "type": "Detected",
#                     "cont": "Find AppClone Vulnerability."
#                 }
#                 send(JSON.stringify(payload));
#             }
#             return this.onPageFinished.overloads[0].apply(this, arguments);
#         }
#     '''
#     return hook_code

def test_case_generator(path):
    testCases = get_testCase(path);
    testCaseCodes = '''
        var testCases = new Array(
    '''
    for testCase in testCases:
        testCaseCodes += "\"" + testCase + "\""
        testCaseCodes += ","
    testCaseCodes = testCaseCodes[:-1]
    testCaseCodes += ")"
    return testCaseCodes


def last_code_assembling(packagename,classname,testCase_path):
    testCaseCodes = ""
    generated_codes = ""
    head_codes = ""

    testCaseCodes = test_case_generator(testCase_path)
    

    generated_codes = build_script_method_open(packagename, 'android.os.ParcelFileDescriptor') + build_script_method_openFile(packagename, classname) + build_script_method_query(packagename, classname)     

    head_codes = '''
        Java.perform(function(){
            var UriClass = Java.use('android.net.Uri');
            var OpenHandler = Java.use('android.os.ParcelFileDescriptor');
            var OpenFile_QueryHandler = Java.use('%(className)s');
            var filename = "";
            %(gc)s
        })
    '''%{"gc":generated_codes,"className":classname}

    final_codes = testCaseCodes + head_codes
    return final_codes


def get_testCase(path):    # read testcases from file.
    testCases = []
    f = open(path,"r")
    for line in f.readlines():
        testCases.append(line.strip())
    f.close()
    return testCases

def begin_instrumentation(appName, script_source):   # apply jscode
    device = frida.get_usb_device()
    try:
        session = device.attach(appName)
    except Exception as e:
        print (colored('[ERROR]: ' + str(e), "red"))
        sys.exit()
    try:
        script = session.create_script(script_source)
        script.on('message', on_message)
        script.load()
    except Exception as e:
        print (colored('[ERROR]: ' + str(e), "red"))
        sys.exit()

def on_message(message, data):
    global overloadNum
    global appClone_script
    if message['type'] == 'send':
        payload = json.loads(message["payload"])
        if payload["type"] == "overloadNum":
            overloadNum = payload["num"];
        elif payload["type"] == "Warning":
            print(colored("[Warn]" + payload["cont"],"red"))
        elif payload["type"] == "Detected":
            print(colored("[Detected!]" + payload["cont"],"red"))
        elif payload["type"] == "triggerfilename":
            print(colored("[TriggerFile]" + payload["filename"],"green"))
            appClone_script.post(payload)
        else:
            print("[*] {0}".format(message['payload']))
    else:
        print(message)

def get_loaded_classes(packagename):  # Demostrate the loaded classes in the corresbonding app. Sometimes it may fail.
    jscode = '''
        Java.perform(function(){
            //Process.setExceptionHandler(callback);
            classes = Java.enumerateLoadedClassesSync();

            //classes = Process.enumerateModulesSync();
            for(var i = 0; i < classes.length; i++){
                console.log(classes[i]);
            }
        })
    '''
    begin_instrumentation(packagename,jscode)

def get_classMethods(packagename,classname):
    jscode = '''
        Java.perform(function(){
            var Handler2 = Java.use('%(className)s');
            var curMethods = Handler2.class.getMethods();
            for(var i = 0; i < curMethods.length; i++){
                var methodname = curMethods[i].toString();
                console.log(methodname);
            }
        })
    '''%{"className":classname}
    print(jscode)
    begin_instrumentation(packagename,jscode)

packagename = "com.facebook.lite"       # package of apk to be tested
packagename0 = "com.sec.tsis.facebookattack"  # package of trigger
classname = "com.facebook.lite.photo.MediaContentProvider"     # class of contentprovider
testcasePath = "cp_fb_testCase"

overloadNum = 0

jscode = last_code_assembling(packagename,classname)
print(jscode)
jscode_trigger = build_script_trigger()
begin_instrumentation(packagename0,jscode_trigger)
appClone_script = begin_instrumentation_Appclone(packagename,jscode)
try:
    sys.stdin.readlines()
except KeyboardInterrupt:
    sys.exit()

                # LoadUrlParams_Handler.$init.overload("java.lang.String").implementation = function(url){
                #     console.log(url);
                #     return this.$init(url);
                # };



        # PlayHistoryProvider.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(a0,a1,a2,a3,a4){
        #     console.log("query1() invoked!");
        #     console.log(a0);
        #     result = this.query(a0,a1,a2,a3,a4);
        #     if(result != null){
        #         console.log("vul detected!");
        #     }
        #     return result;


        # }

        # for (var i = 0; i < currentMethods.length; i++){
        #     console.log(currentMethods[i].toString());
        #     var items = currentMethods[i].toString().split('(')[0].split(' ');
        #     console.log(items);
        #     var currentMethodName = items[items.length - 1];
        #     console.log(currentMethodName);
        #     currentMethodName = currentMethodName.replace('com.sohu.sohuvideo.provider.PlayHistoryProvider', '');
        #     console.log(currentMethodName);
        #     if (currentMethodName.split('.').length-1 > 1) {
        #         continue
        #     } else {
        #         currentMethodName = currentMethodName.replace('.', '');
        #     }
        #     console.log(currentMethodName);
        #     var overload_count = PlayHistoryProvider[currentMethodName].overloads.length;
        #     console.log(overload_count);
        # }

        # script = session.create_script("""
  # Java.perform(function() {
  #     var PlayHistoryProvider = Java.use('com.sohu.sohuvideo.provider.PlayHistoryProvider');
  #     send("Start...");

  #       var overload_count = PlayHistoryProvider['query'].overloads.length;
  #       console.log(overload_count);

  #       PlayHistoryProvider.query.overloads[0].implements = function(a0,a1,a2,a3,a4){
  #           console.log("query() invoked!");
  #           console.log(a0);
  #           result = this.query(a0,a1,a2,a3,a4);
  #           if(result != null){
  #               console.log("vul detected!");
  #           }
  #           return result;
  #       }
  # })

  # def build_script_hookMethods(overloadNum, classname, methodname):
#     generated_codes = ""
#     if overloadNum == 0:
#         print(colored('[ERROR]:Can\'t find method \'' + methodname + '\'', "red"))
#     else:
#         hook_code = '''
#             var OpenFileHandler = Java.use('%(className)s');
#             var count = 0;
#             OpenFileHandler.%(methodName)s.overloads[i].implementation = function(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15){
#                 console.log("ori:" + arguments[0]);
#                 arguments[0] = UriClass.parse(testCases[count]);
#                 console.log("now:" + arguments[0]);
#                 count+=1;
#                 if(count >= testCases.length){
#                     count = testCases.length-1;
#                     var payload = {
#                         "type": "Warning",
#                         "cont": "TestCases has run out!"
#                     }
#                     send(JSON.stringify(payload));
#                 }
#                 var result = this.%(methodName)s.overloads[i].apply(this, arguments);
#                 if(result != null){
#                     console.log("vul detected!");
#                 }
#                 return result;
#             }
#         '''%{"className":classname,"methodName":methodname}
#         for index in range(0,overloadNum):
#             f_hook_code = hook_code.replace("overloads[i]", "overloads[" + str(index) +"]")
#             generated_codes+=f_hook_code


#     final_codes = '''
#         Java.perform(function(){
#             var UriClass = Java.use('android.net.Uri')
#             %s
#         })
#     '''%(generated_codes)

#     testCases = get_testCase()
#     testCaseCodes = '''
#         var testCases = new Array(
#     '''
#     for testCase in testCases:
#         testCaseCodes += "\"" + testCase + "\""
#         testCaseCodes += ","
#     testCaseCodes = testCaseCodes[:-1]
#     testCaseCodes += ")"

#     final_codes = testCaseCodes + final_codes
#     return final_codes


            