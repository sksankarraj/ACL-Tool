import win32security
import os
import shutil
import sys
from datetime import datetime
from os.path import dirname, abspath
import xlsxwriter

f_path = os.path.join(str(sys.argv[1]))
t_path = os.path.join(str(sys.argv[2]))
mod_date = os.path.join(str(sys.argv[3]))
rep_path = os.path.join(str(sys.argv[4]))

All_perms = {
    1: "ACCESS_READ",  # 0x00000001
    2: "ACCESS_WRITE",  # 0x00000002
    4: 'ACCESS_CREATE',  # 0x00000004
    8: "ACCESS_EXEC",  # 0x00000008
    16: "ACCESS_DELETE",  # 0x00000010
    32: "ACCESS_ATTRIB [sic]",  # 0x00000020
    64: "ACCESS_PERM",  # 0x00000040
    32768: "ACCESS_GROUP",  # 0x00008000
    65536: "DELETE",  # 0x00010000
    131072: "READ_CONTROL",  # 0x00020000
    262144: "WRITE_DAC",  # 0x00040000
    524288: "WRITE_OWNER",  # 0x00080000
    1048576: "SYNCHRONIZE",  # 0x00100000
    16777216: 'ACCESS_SYSTEM_SECURITY',  # 0x01000000
    33554432: "MAXIMUM_ALLOWED",  # 0x02000000
    268435456: "GENERIC_ALL",  # 0x10000000
    536870912: "GENERIC_EXECUTE",  # 0x20000000
    1073741824: "GENERIC_WRITE",  # 0x40000000
    65535: "SPECIFIC_RIGHTS_ALL",  # 0x0000ffff
    983040: "STANDARD_RIGHTS_REQUIRED",  # 0x000f0000
    2031616: "STANDARD_RIGHTS_ALL",  # 0x001f0000
}

Typical_perms = {
    2032127: "Full Control(All)",
    1179817: "Read(RX)",
    1180086: "Add",
    1180095: "Add&Read",
    1245631: "Change"
}

CONVENTIONAL_ACES = {
            win32security.ACCESS_ALLOWED_ACE_TYPE: "ALLOW",
            win32security.ACCESS_DENIED_ACE_TYPE: "DENY"
        }

def createDir(subpath, temp_tpath):
    dacl = win32security.GetNamedSecurityInfo(subpath, win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
    if not os.path.exists(temp_tpath):
        os.makedirs(temp_tpath)
        win32security.SetNamedSecurityInfo(temp_tpath,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
            None,
            None, 
            dacl, 
            None)
    return dacl

def getReport(sourc, dest, mod_date):
    c = 0
    r = 0
    if rep_path != '':
        workbook = xlsxwriter.Workbook(rep_path)
    else:
        workbook = xlsxwriter.Workbook('report.xlsx')
    worksheet = workbook.add_worksheet()
    for root, dir, file in os.walk(sourc):
        if c == 0:
            dacl = createDir(root, dest + root[root.rindex('\\'):])
            c = +1
            for n_ace in range(dacl.GetAceCount()):
                ace = dacl.GetAce(n_ace)
                (ace_type, ace_flags) = ace[0]
                if ace_type in CONVENTIONAL_ACES:
                    mask, sid = ace[1:]
                else:
                    mask, object_type, inherited_object_type, sid = ace[1:]
                name, domain, type = win32security.LookupAccountSid(None, sid)
                
                r = r + 1
                if Typical_perms.has_key(mask):
                    mask_name = Typical_perms[mask]
                elif All_perms.has_key(mask):
                    mask_name = All_perms[mask]
                else:
                    mask_name = "none"
                #print "%s %s\\%s %d %s %d" % (CONVENTIONAL_ACES.get(
                    #ace_type, "OTHER"), domain, name, mask, mask_name, r)
                worksheet.write(r, 0, root)
                worksheet.write(r, 1, "%s\\%s" % (domain, name))
                worksheet.write(r, 2, mask_name)
                worksheet.write(r, 3, CONVENTIONAL_ACES.get(ace_type, "OTHER"))
        for dName in dir:
            subpath = os.path.join(root, dName)
            temp_tpath = dest + subpath.replace(sourc[:sourc.rindex('\\')],'')
            dacl = createDir(subpath, temp_tpath)
            for n_ace in range(dacl.GetAceCount()):
                ace = dacl.GetAce(n_ace)
                (ace_type, ace_flags) = ace[0]
                if ace_type in CONVENTIONAL_ACES:
                    mask, sid = ace[1:]
                else:
                    mask, object_type, inherited_object_type, sid = ace[1:]
                name, domain, type = win32security.LookupAccountSid(None, sid)
                
                r = r + 1
                if Typical_perms.has_key(mask):
                    mask_name = Typical_perms[mask]
                elif All_perms.has_key(mask):
                    mask_name = All_perms[mask]
                else:
                    mask_name = "none"
                #print "%s %s\\%s %d %s %d" % (CONVENTIONAL_ACES.get(
                    #ace_type, "OTHER"), domain, name, mask, mask_name, r)
                worksheet.write(r, 0, subpath)
                worksheet.write(r, 1, "%s\\%s" % (domain, name))
                worksheet.write(r, 2, mask_name)
                worksheet.write(r, 3, CONVENTIONAL_ACES.get(ace_type, "OTHER"))
        for name in file:
            subpath = os.path.join(root, name)
            temp_tpath = dest + root.replace(sourc[:sourc.rindex('\\')],'')
            print 'moving' + subpath
            if datetime.strptime(mod_date, "%d/%m/%Y") > datetime.fromtimestamp(os.path.getmtime(subpath)):
                shutil.copy(subpath, temp_tpath)
    workbook.close()
    return
getReport(f_path, t_path, mod_date)
