
import xml.etree.ElementTree as ET
import shutil
import argparse
import tempfile
import os
import subprocess

ANDROIDMANIFEST_FILENAME = "./AndroidManifest.xml"
CA_FILENAME = os.getenv('HOME') + '/usr-android/etc/cacert.der'

NETWORK_SECURITY_CONTENT = ('<?xml version="1.0" encoding="utf-8"?>\n'
                            '<network-security-config>\n'
                            '   <base-config>\n'
                            '       <trust-anchors>\n'
                            '           <certificates src="@raw/cacert"/>\n'
                            '           <certificates src="system"/>\n'
                            '       </trust-anchors>\n'
                            '   </base-config>\n'
                            '</network-security-config>\n'
                            )

args = None

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    # from whichcraft import which
    from shutil import which
    which(name)
    return which(name) is not None

def run_cmd(cmd, verbose=None):
    """Run command."""
    if args.verbose:
        print("Running: ", end='') 
        print(" ".join(str(x) for x in cmd)) 
    r = subprocess.run(cmd)
    if r.returncode:
        raise ValueError(f'Error: running {cmd[0]}')

def init():
    """init args and check dependencies."""
    global args
    parser = argparse.ArgumentParser(
        description="Tool to add custom CA Authority into an APK. For more info see https://developer.android.com/training/articles/security-config")

    optional = parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    required.add_argument("-c", "--cert", nargs="?", required=True, 
                        help="CA certificate file (DER format)")

    optional.add_argument("-i", "--input", nargs="?",
                        help="APK file, extracted folder or AndroidManifest.xml (Default current directory)", type=str, default=".")

    optional.add_argument("-of", "--output_file", nargs="?",
                        help="APK file")

    optional.add_argument("-od", "--output_dir", nargs="?",
                        help="Output directory")

    optional.add_argument("-v", "--verbose",
                        help="increase output verbosity", action="store_true")
    
    parser._action_groups.append(optional)
    args = parser.parse_args()

    if not os.path.exists(args.input):
        raise ValueError(f'Error: {args.input} does not exists')

    # input apk mode
    if os.path.isfile(args.input):
        for tool in [ 'apktool' ]:
            if not is_tool(tool):
                raise ValueError(f'Error: tool {tool} is not in path')
        if not args.output_file and not args.output_dir:
            args.output_file = os.path.splitext(args.input)[0] + '-patched.apk'
    
    # output apk mode
    if args.output_file:
        for tool in [ 'apktool', 'zipalign', 'apksigner' ]:
            if not is_tool(tool):
                raise ValueError(f'Error: tool {tool} is not in path')
    
    args.clean_output_dir = False
    if not args.output_dir:
        args.output_dir = os.path.splitext(args.input)[0]
        args.clean_output_dir = True

def run():
    """run tool."""
    androidmanifest_filename = ANDROIDMANIFEST_FILENAME

    if os.path.isfile(args.input):
        cmd = ['apktool', 'decode', '-f', '-o', args.output_dir, args.input]
        run_cmd(cmd, verbose = args.verbose)
        androidmanifest_filename = args.output_dir + "/" + ANDROIDMANIFEST_FILENAME

    shutil.copyfile(androidmanifest_filename, androidmanifest_filename + '-backup')
    patch_androidmanifest(androidmanifest_filename, args.cert)

    if args.output_file:
        tmp_file = args.output_file + "tmp"
        # build apk
        cmd = ['apktool', 'build', args.output_dir, '-o', tmp_file]
        run_cmd(cmd, verbose = args.verbose)

        # remove tmp dir
        if args.clean_output_dir and os.path.isdir(args.output_dir):
            shutil.rmtree(args.output_dir)

        # zipalign
        cmd = ['zipalign', '-v', '-f', '-p', '4', tmp_file, args.output_file]
        run_cmd(cmd, verbose = args.verbose)
        os.unlink(tmp_file)

        # apksign
        delete_keystore = False
        if not os.path.isfile("debug.keystore"):
            cmd = 'keytool -genkey -v -keystore debug.keystore -storepass debug00 -keypass debug00 -alias signkey -dname CN=Debug_CA -keyalg RSA -keysize 2048 -validity 20000'.split(sep=None)
            run_cmd(cmd, verbose = args.verbose)
            delete_keystore = True
        cmd = ['apksigner', 'sign', '--ks', 'debug.keystore', '--ks-key-alias', 'signkey', '--ks-pass', 'pass:debug00', '--key-pass', 'pass:debug00', args.output_file ]
        run_cmd(cmd, verbose = args.verbose)
        if delete_keystore:
            os.unlink('debug.keystore')

def register_all_namespaces(filename):
    """Register all namespaces"""
    namespaces = dict(
        [node for _, node in ET.iterparse(filename, events=['start-ns'])])
    #namespaces = {node for _, node in ET.iterparse(filename, events=['start-ns'])}
    for namespace in namespaces:
        ET.register_namespace(namespace, namespaces[namespace])


def patch_androidmanifest(androidmanifest_filename, ca_filename):
    """Patch androidmanifest to include network_security.xml"""
    folder = os.path.dirname(androidmanifest_filename)
    # register namespaces
    register_all_namespaces(androidmanifest_filename)
    # parse xml
    #tree = ET.parse(r"./AndroidManifest.xml")
    tree = ET.parse(androidmanifest_filename)
    root = tree.getroot()
    # get package name
    # packagename = root.attrib["package"]
    # print(packagename)
    # get application node
    application = root.find("application")
    # modify it
    application.set('android:networkSecurityConfig',
                    '@xml/network_security_config')
    
    # save
    xml_string = ET.tostring(root, encoding='utf-8', method='xml').decode()
    # tree.write("output.xml")
    with open(androidmanifest_filename, 'w+') as file:
        file.write(xml_string)

    # create res/xml/network_security.xml
    os.makedirs(folder + '/res/xml', exist_ok=True)
    with open(folder + '/res/xml/network_security_config.xml', 'w+') as file:
        file.write(NETWORK_SECURITY_CONTENT)

    # create res/raw/cacert
    os.makedirs(folder + '/res/raw', exist_ok=True)
    shutil.copyfile(ca_filename, folder + '/res/raw/cacert')


def __main__():
    """main."""
    global args
    init()
    run()


# command line run main
if __name__ == "__main__":
    __main__()
