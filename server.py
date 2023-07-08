#!/usr/bin/env python
# This is a simple web server for a time recording application.
# It's your job to extend it by adding the backend functionality to support
# recording the time in a SQL database. You will also need to support
# user access/session control. You should only need to extend this file.
# The client side code (html, javascript and css) is complete and does not
# require editing or detailed understanding.
'''Module docstring'''
# import the various libraries needed
import http.cookies as Cookie   # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import json   # support for json encoding
import sys    # needed for agument handling
#import time   # time support
import random # for random number generation
import sqlite3 #sqlite3

'''This function fetches the contents from SQL database for specified conditions'''
def select_sql_command(content,list_of_items):
    with sqlite3.connect('database.db') as connect:
        cursor = connect.cursor()
        rows = cursor.execute(content,list_of_items).fetchall()
        print("SQLite Data Fetched:",rows)
    return rows

'''This function will be use to modifiy values in SQL database for specified conditions'''
def modify_sql_command(content,list_of_items):
    with sqlite3.connect('database.db') as connect:
        cursor = connect.cursor()
        cursor.execute(content,list_of_items)
        print("Database created and Successfully Connected to SQLite")

'''This function is to select values from SQL databse'''
def select_sql_command_all(content):
    with sqlite3.connect('database.db') as connect:
        cursor = connect.cursor()
        rows = cursor.execute(content).fetchall()
        print("SQLite Data Fetched:",rows)
    return rows 

def build_remove_instance(id):
    """This function builds a remove_instance action that allows an
       activity instance to be removed from the index.html web page"""
    return {"type":"remove_instance","id":id}

def build_remove_activity(id):
    """This function builds a remove_activity action that allows
       an activity type to be removed from the activity.html web page"""
    return {"type":"remove_activity","id":id}

def build_response_message(code, text):
    """This function builds a message action that displays a message
       to the user on the web page. It also returns an error code."""
    return {"type":"message","code":code, "text":text}

def build_response_fetch_summary(id,period,interr,interd, ttime):
    """This function builds a summary response that contains one summary table entry."""
    return {"type":"summary","id":id, "periods":period,"interrupted":interr,"interrupting":interd,"time":ttime}

def build_response_activity(id, name):
    """This function builds an activity response that contains the id and name of an activity type,"""
    return {"type":"activity", "id":id, "name":name}

def build_response_instance(id,note,activityid,timestamp):
    """This function builds an instance response that contains the id,timestamp and note"""
    return {"type":"instance", "id":id, "note":note, 'activityid':activityid, "timestamp":timestamp}

def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, it should be the only response provided."""
    return {"type":"redirect", "where":where}

def handle_validate(iuser, imagic): 
    """Decide if the combination of user and magic is valid"""
    session_id = select_sql_command('''SELECT sessionid FROM session
    WHERE userid=? and magic=?''',(iuser,imagic))
    print('iuser:',iuser)
    print('imagic:',imagic)
    return bool(len(session_id)>0)

def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    modify_sql_command("DELETE FROM session where userid = ? and magic = ?",(iuser,imagic))


# The following handle_..._request functions are 
# invoked by the corresponding /action?command=.. request
def handle_login_request(iuser, imagic, content):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    if handle_validate(iuser, imagic) is True:
        print('iuser:',iuser)
        print('imagic:',imagic) #the user is already logged in, so end the existing session.
        handle_delete_session(iuser, imagic)
    response = []
    if len(content) > 0: ### The user is valid
        username = content['username']
        #print('username:',username)
        password = content['password']
        #print('password:',password)
        users_db = select_sql_command('''SELECT username,password 
        FROM users WHERE username=? and password=?''',(username,password))
        #print('returned:',users_db) #change name of returned
        print('length of returned:',len(users_db))
        if len(users_db) == 0:  #user is not valid
            if username == '' and password == '':
                response.append(build_response_message(100,'Missing Username and Password'))
                user = ''
                magic = ''
            elif username == '':
                response.append(build_response_message(110,'No Username Provided'))
                user = '!'
                magic = ''
            elif password == '':
                response.append(build_response_message(150,'No Password Provided'))
                user = ''
                magic = '!'
            else:
                response.append(build_response_message(200, 'Invalid password'))
                user = '!'
                magic = ''
        #if username has a session, delete session and create a new one
        else: ## check if the password matches
            response.append(build_response_redirect('/index.html'))
            userid= select_sql_command('''select userid from users
            where username=? and password = ?''', (username, password))
            #print('Userid:',userid)
            user = userid[0][0] 
            #print("User", user)
            magic = random.randint(0,1234567890) #user = 'test' ## username or userid
            #print("password", magic)
            session = select_sql_command_all("select max(sessionid),userid from session")
            #print('session:',session)
            session_id = session[0][0]
            user_loggedin = session[0][1]
            print("Session_id", session_id)
            print('User_loggedin:',user_loggedin)
            print(len(session))
            if str(user) == str(user_loggedin):
                print("Logged In")
                modify_sql_command("DELETE FROM session WHERE userid=?",(user,))
            modify_sql_command("INSERT INTO session VALUES (NULL,?,?) ", (user, magic))
    else:
        response.append(build_response_redirect('/login.html'))
        user = '!'
        magic = ''
    return [user, magic, response]

def handle_logout_request(iuser,imagic,parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    else:
        if parameters['command'] == '' or parameters['command'] is None:
            response.append(build_response_message(100,'Command Not Found'))
        else:
            current_session = select_sql_command('SELECT magic FROM session WHERE userid=? and magic=?',(iuser,imagic))
            print('len_current_session',len(current_session))
            if len(current_session) > 0:
                handle_delete_session(iuser, imagic)
                response.append(build_response_redirect('/logout.html'))
            else: 
                response.append(build_response_redirect('/login.html'))
    user = iuser
    magic = imagic
    return [user, magic, response]

def handle_summary_request(iuser, imagic, content): #remove content?
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    if handle_validate(iuser, imagic) is not True:
       response.append(build_response_redirect('/login.html'))
    elif content['command'] == 0 or content['command'] is None:
        response.append(build_response_message(100,'Command Not Found'))
    else:
        activity_db = select_sql_command('''SELECT activityid FROM activity
        JOIN session using(userid)
        WHERE userid=? and magic =?''',(iuser,imagic))
        activity_instance_db = select_sql_command('''SELECT instanceid,activityid,start,end
        FROM instance JOIN session using(userid) WHERE userid=? and magic=?
        ''',(iuser,imagic))
        actv_with_noinstance_list = list(map(lambda a: a[0], activity_db))
        actv_with_instance_list = list(map(lambda i: i[1], activity_instance_db))
        period_db = select_sql_command('''SELECT activityid,COUNT(activityid) FROM instance LEFT JOIN activity using(activityid)
        JOIN session using(userid) WHERE activity.userid=? and session.magic=?
        GROUP BY activityid ORDER BY instanceid ASC''',(iuser,imagic))
        period_activity = list(map(lambda i: i[0], period_db))
        period=0
        summaries = []
        for actv in actv_with_noinstance_list:
            if actv not in (i for i in actv_with_instance_list): 
                summaries.append((actv,0,0,0,0))
                #response.append(build_response_fetch_summary(actv,0,0,0,0))
        for actv in period_activity:
            print('_______')
            period_count = select_sql_command('''SELECT count(instanceid) FROM instance
            WHERE activityid=? GROUP BY activityid''',(actv,))
            period = period_count[0][0]
            instance_db = select_sql_command('''SELECT instanceid,start,end,activityid FROM instance
            LEFT JOIN activity using(activityid)
            JOIN session using(userid) WHERE activity.userid=? and magic=? and activityid=?''',(iuser,imagic,actv))
            interrupted_count = 0
            interrupting_count = 0
            same_activity_time = 0
            time= 0
            for i in instance_db:
                #print('instance_i-',i)
                interrupted_count_db = select_sql_command('''SELECT COUNT(*) 
                FROM instance WHERE (userid = ?) and
                ((start > ? and start < ?) or (instanceid > ? and start = ? ))''',(iuser,i[1],i[2],i[0],i[1]))
                interrupted_count += interrupted_count_db[0][0]
                interrupting_count_db = select_sql_command('''SELECT COUNT(*)
                FROM instance WHERE (userid = ?) and
                ((start < ? and end > ?) or (instanceid < ? and start = ? ))''',(iuser,i[1],i[1],i[0],i[1]))
                interrupting_count += interrupting_count_db[0][0]
                time_db = select_sql_command('''SELECT start,end
                FROM instance WHERE (userid = ?) and
                ((start > ? and start < ?) or (instanceid > ? and start = ? ))
                ORDER BY start''',(iuser,i[1],i[2],i[0],i[1])) 
                actv_time = round(abs(i[2]-i[1]))
                if len(time_db) > 1:  #instance interrupted more than once, which have a few cases
                    time_interrupted = 0
                    print('instance_interrupted_more',i[0])
                    p_end = 0
                    for index,time in enumerate(time_db):
                        m_start = i[1]
                        m_end = i[2]
                        new_start = time_db[index][0]
                        new_end = time_db[index][1]
                        #print('new_end',new_end)
                        #print('p_end',p_end)
                        if new_end > p_end:
                            if (p_end > new_start) and (new_end < m_end):
                                print('Check 1- Multiple activity interruption')
                                time_interrupted += round(abs(new_end - p_end))
                            elif (p_end > new_start) and (new_end > m_end):
                                print('Check 2- Multiple activity interruption')
                                #print('p_end',p_end)
                                time_interrupted += round(abs(m_end - p_end))
                                #print('check 2 time',round(abs(m_end - p_end)))
                            elif new_start >= m_start:
                                if new_end < m_end: #if activtiy ended before main_activity
                                    print('check3 - 1 interruption')
                                    time_interrupted += round(abs(new_end - new_start))
                                else: #if activtiy ended after main_activtiy
                                    print('check4 - 1 interruption')
                                    time_interrupted += round(abs(m_end - new_start))
                            p_end = time[1]
                        #print('time_interrupted',time_interrupted)
                    time = round(abs(actv_time - time_interrupted))
                    print('Time_interrupted more than once',time)
                elif len(time_db) == 1: #instance interuppted once
                    if time_db[0][1] < i[2]:
                        time = round(abs((actv_time)-(time_db[0][1] - time_db[0][0]))) #if new_actv end before p_actv
                    else:
                        time = round(abs(actv_time - (i[2]-time_db[0][0]))) #time_db[0][0] gets start time of activity interrupting
                    print('Time_interrupted once',time)
                else:
                    print('instance_not_interrupted',i[0])
                    time = round(abs(actv_time))
                    print('Time_not interrupted',time)
                same_activity_time += time
                print('_______')
            summary_list = (actv,period,interrupted_count,interrupting_count,same_activity_time)
            summaries.append(summary_list)
            summaries.sort(reverse=True, key = lambda i: i[4])
        for i in summaries:
            response.append(build_response_fetch_summary(i[0],i[1],i[2],i[3],i[4]))
    user = iuser
    magic = imagic
    return [user, magic, response]

def handle_get_activities_request(iuser, imagic):
    """This code handles a request for an update to the session summary values.
    You will need to extract this information from the database.
    You must return a value for all vehicle types, even when it's zero."""
    response = []
    activity_values = select_sql_command('''SELECT activityid,name FROM activity 
    JOIN session using(userid)
    WHERE session.userid=? and session.magic=?''',(iuser,imagic))
    if handle_validate(iuser,imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    else:
        for i in activity_values:
            response.append(build_response_activity(i[0],i[1]))
    print('response_activites:',response)
    user = iuser
    magic = imagic
    return [user, magic, response]

def handle_get_instances_request(iuser, imagic):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    instance_db = select_sql_command('''SELECT instanceid,comment,activityid,start
    FROM instance LEFT JOIN activity using(activityid)
    JOIN session using(userid)
    WHERE activity.activityid = instance.activityid 
    and session.userid=? and session.magic=? and instance.end= ?
    ORDER BY instance.start''',(iuser,imagic,0))
    print('instance_db:',instance_db)
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    else:
        for i in instance_db:
            response.append(build_response_instance(i[0],i[1],i[2],i[3])) 
    print('getinstance_response:',response)
    user = iuser
    magic = imagic
    return [user, magic, response]

def handle_begin_instance_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    print('begin_content:',content) #returns activityid, start,timestamp and not
    if handle_validate(iuser,imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    else:
        if content['id'] <= 0:
            response.append(build_response_message(200,'Invalid Activity'))
        elif content['id'] == '' or content['id'] is None:
            response.append(build_response_message(100,'Activityid Missing'))
        elif content['timestamp']== '' or content['timestamp'] is None:
            response.append(build_response_message(100,'Timestamp Missing'))
        elif content['timestamp'] <= 0:
            response.append(build_response_message(200,'Invalid Timestamp'))
        elif isinstance(content['timestamp'],int) is False:
            response.append(build_response_message(250,'Invalid Timestamp'))
        instance_db = select_sql_command('''SELECT instanceid,activityid,start 
        FROM instance JOIN session using(userid)
        WHERE session.userid=? and session.magic=?''',(iuser,imagic))
        if len(instance_db) >= 0:
            response.append(build_response_message(0, "Activity Started"))
            modify_sql_command('''INSERT INTO instance VALUES(NULL,?,?,?,0,?)''',
            (iuser,content['id'],content['timestamp'],content['note']))
            new_instanceid = select_sql_command('''SELECT instanceid FROM instance 
            WHERE userid=? and comment=? and start=?''',(iuser,content['note'],content['timestamp']))
            print('new_id:',new_instanceid[0][0])
            response.append(build_response_instance(new_instanceid[0][0],content['note'],content['id'],content['timestamp']))
    user = iuser #''
    magic = imagic #''
    return [user, magic, response]

def handle_end_instance_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    print('end_content:',content)
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    else:
        end_instance = select_sql_command('''SELECT instanceid,activityid,end
        FROM instance JOIN session 
        ON instance.userid=session.userid WHERE session.userid=?''',(iuser))
        for i in end_instance:
            if content['id'] != i[1] or content['id'] <= 0:
                response.append(build_response_message(200,'Invalid Activityid'))
            elif content['id'] == '' or content['id'] is None:
                response.append(build_response_message(100,'Missing Activityid'))
            elif content['timestamp']=='' or content['timestamp'] is None:
                response.append(build_response_message(100,'Missing Timestamp'))
            elif isinstance(content['timestamp'],int) is False:
                response.append(build_response_message(200,'Invalid Timestamp'))
            elif content['timestamp'] <= 0:
                response.append(build_response_message(250,'Invalid Timestamp'))
            elif content['timestamp'] != i[2]:
                response.append(build_response_message(290,'Incorrect Timestamp'))
            elif content['timestamp'] > i[2]:
                response.append(build_response_message(220,'Activity has already ended'))
        if len(end_instance) > 0:   #should I change this
            response.append(build_response_message(0, "Activity Ended"))
            response.append(build_remove_instance(content['id']))
            modify_sql_command('''UPDATE instance SET end=? WHERE instanceid=? and userid=?''',
            (content['timestamp'],content['id'],iuser))
        else:
            response.append(build_response_message(200,'Acitivity Id is invalid'))
    print('end_response:',response)
    user = iuser #''
    magic = imagic #''
    return [user, magic, response]

def handle_add_activity_request(iuser, imagic, content): #we want to append activity values into database and create new ones in frontend
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    db_activity = select_sql_command('''SELECT activity.userid,name
    FROM activity JOIN session using(userid)
    WHERE session.userid=? and session.magic=?''',(iuser,imagic))
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    elif len(content)>0 and ('name' in content):
        print('content', content)
        # if content['name'] != True:
        #     print(content['name'])
        #     response.append(build_response_message(100,'Activity Name Missing')) #check if response is right
        if content['name'] == '' or content['name'] is None:
            response.append(build_response_message(110,'Activity Name Missing'))
        elif isinstance(content['name'],str) is False:
            response.append(build_response_message(220,'Activity name is not a string'))
        elif content['command'] =='' or content['command'] is None:
            response.append(build_response_message(100,'Command Not Found'))
        else:
            db_name = list(map(lambda x: x[1], db_activity))
            print('db_name_list:',db_name)
            if content['name'] in db_name:
                response.append(build_response_message(200,'Activity Already Exists'))
            elif content['name'] not in db_name:
                modify_sql_command("INSERT INTO activity VALUES (NULL,?,?)",(iuser,content['name']))
                activity_count = select_sql_command('''SELECT activityid FROM activity JOIN session using(userid)
                WHERE session.userid=? and activity.name=?''',(iuser,content['name']))
                response.append(build_response_message(0, "Activity Type Added"))
                response.append(build_response_activity(activity_count[0][0],content['name']))
    user = iuser #''
    magic = imagic #''
    return [user, magic, response]

def handle_delete_activity_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/login.html'))
    else:
        if content['id'] == '' or content['id'] is None:
            response.append(build_response_message(100,'Activity Name Missing'))
        elif isinstance(content['id'],int) is False:
            response.append(build_response_message(200,'Activityid Invalid'))
        elif content['command'] =='' or content['command'] is None:
            response.append(build_response_message(200,'Command Not Found'))
        else:
            response.append(build_response_message(0, "Activity Type Deleted"))
            response.append(build_remove_activity(content["id"]))
            #print('content:',content)
            id = content['id']
            modify_sql_command('DELETE FROM activity WHERE activityid=?',(id,))
    user = iuser
    magic = imagic
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # POST This function responds to GET requests to the web server.
    def do_POST(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path) # type: ignore 
        # Decided what to do based on the file requested.

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        if parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request

            # extract the content from the POST request.
            # This are passed to the handlers.
            length =  int(self.headers.get('Content-Length'))
            scontent = self.rfile.read(length).decode('ascii')
            print(scontent)
            if length > 0 :
              content = json.loads(scontent)
            else:
              content = []

            # deal with get parameters
            parameters = urllib.parse.parse_qs(parsed_path.query)# type: ignore
            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], content)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'get_activities':
                    [user, magic, response] = handle_get_activities_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'get_instances':
                    [user, magic, response] = handle_get_instances_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'begin_instance':
                    [user, magic, response] = handle_begin_instance_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'end_instance':
                    [user, magic, response] = handle_end_instance_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'add_activity':
                    [user, magic, response] = handle_add_activity_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'delete_activity':
                    [user, magic, response] = handle_delete_activity_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'fetch_summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    #response.append(build_response_refill('message', 901, 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                #response.append(build_response_refill('message', 902,'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

   # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)# type: ignore
        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()