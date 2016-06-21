import gcm
import base64
import sqlite3
import datetime
from argparse import ArgumentParser

# Author : n0fate
# Contacts : n0fate@n0fate.com
# License : GPL2

# Presentation : http://forensic.n0fate.com/wp-content/uploads/2012/12/Forensic-artifacts-for-Yosemite-call-history-and-sms-anlaysis-ENG.pdf
# Call History Decryptor
# Algorithm : AES128-GCM

class CallHistoryDecryptor:
    def __init__(self):
        self.Filename = ''  # Open Filename
        self.con = ''  # SQLite3 Connector
        self.cur = ''  # Cursor
        self.key = ''

    def open(self, filename):
        self.Filename = filename

        if self.Filename == '':
            return False

        self.con = sqlite3.connect(self.Filename)

        self.cur = self.con.cursor()

        return True

    def close(self):
        self.con.close()

    def gettablelist(self):
        try:
            self.cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        except sqlite3.DatabaseError:
            return []

        self.TableList = self.cur.fetchall()
        return self.TableList

    def getcolumnnamebytable(self, Tablename):
        """

        :param Tablename:
        :return:
        """
        if not (Tablename in self.TableList):
            return [], False

        try:
            cursor = self.con.execute('SELECT * FROM %s' % Tablename)
        except sqlite3.DatabaseError:
            return []
        r = cursor.fetchone()
        colnames = list(map(lambda x: x[0], cursor.description))
        return colnames, True

    def getrecordsbytable(self, Tablename):
        if not (Tablename in self.TableList):
            return [], False
        try:
            cursor = self.cur.execute('SELECT * FROM %s' % Tablename)
        except sqlite3.DatabaseError:
            return [], False

        colnames = cursor.fetchall()
        return colnames, True

    def decryptcallhistorydb(self, blob):
        iv = blob[0x10:0x20]
        data = blob[0x20:]
        tag = blob[0:0x10]
        auth_data = ''
        decrypted = gcm.gcm_decrypt(self.key, iv, data, auth_data, tag)
        return decrypted

    def setkey(self, key):
        self.key = key


def main():
    print 'Call History Decryptor for OS X Yosemite (Written by n0fate)'
    print 'It can decrypt a call-history in OS X.'
    print 'Continuity in OS X : https://www.apple.com/osx/continuity/'

    parser = ArgumentParser()
    parser.add_argument("-k", "--key", dest="keyvalue", help="Decoded key as Call History User Data Key in Keychain")
    parser.add_argument("-f", "--file", dest="dbname", help="Call history database (CallHistory.storedata")

    args = parser.parse_args()

    if not(args.keyvalue and args.dbname):
        parser.error('[+] Error : add -k and -f option')

    try:
        key = base64.decodestring(args.keyvalue)
    except:
        print '[+] Error : key format is not base64 encoded'
        return

    print '[+] Key is %s'%key.encode('hex')

    dbname = args.dbname
    print '[+] Open the database : %s'%dbname

    decryptor = CallHistoryDecryptor()
    decryptor.open(dbname)
    ret = decryptor.open(dbname)

    if ret is False:
        print '[+] Error : Invalid db file'
        return

    print '[+] Get a list of table'

    tablelist = decryptor.gettablelist()
    #print tablelist

    print '[+] Get a list of columns in %s table'%tablelist[1]
    column, ret = decryptor.getcolumnnamebytable(tablelist[1])

    #print column

    print '[+] Get a list of records in %s table'%tablelist[1]
    records, ret = decryptor.getrecordsbytable(tablelist[1])

    if ret is False:
        return

    #print records

    decryptor.setkey(key)

    d = datetime.datetime.strptime("01-01-2001", "%m-%d-%Y")

    from tableprint import columnprint

    print '[+] Result'
    header = ['Time(UTC+0)','Answered','Sent','Type','Phone Number', '']
    
    rows = []
    for record in records:
        time = record[column.index('ZDATE')]
        time_osx = d + datetime.timedelta(seconds=time)
        time_converted = time_osx.strftime("%a, %d %b %Y %H:%M:%S")

        ans = record[column.index('ZANSWERED')]

        decrypted = decryptor.decryptcallhistorydb(record[column.index('ZADDRESS')])
        row = [time_converted, 'Yes' if int(ans) == 1 else 'No', 'Yes' if int(record[column.index('ZORIGINATED')]) == 1 else 'No', 'CellPhone' if int(record[column.index('ZCALLTYPE')]) == 1 else 'FaceTime', str(decrypted), '']
        rows.append(row)
    
    mszlist = [-1, -1, -1, -1, -1, -1]
    columnprint(header, rows, mszlist)

    exit()

if __name__ == "__main__":
    main()








