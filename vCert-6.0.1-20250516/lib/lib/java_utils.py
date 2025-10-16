#!/usr/bin/python3

# Copyright (c) 2025 Broadcom. All Rights Reserved.
# The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# Java property file support is provided because for VC 9.0 the file:
#    /usr/lib/vmware-sso/vmware-sts/conf/server.xml
# Indicated in lib/constants.py by:
#    STS_SERVER_CONFIG_FILE_PATH
# has been changed to the Java property file:
#    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties
# Indicated in lib/constants.py by:
#    STS_SERVER_CONFIG_PROPERTY_FILE_PATH

def load_property_file(file=None):
    """
    Load Java property list file.
    """
    properties = {}
    with open(file) as f:
        for line in f:
            line = line.strip()
            keypath, value = line.split('=', 1)

            # The following commented out code loads the property file using
            # nested dictionaries, following the hierarchy defined by the
            # dotted key path. However, current usage doesn't require that, so
            # for now we simply load the file as a simple dictionary to
            # simplify key lookups with the current code.
            #
            # keys = keypath.split('.')
            # keyDict = properties
            # for key in keys[:-1]:
            #     if key not in keyDict:
            #         keyDict[key] = {}
            #     keyDict = keyDict[key]
            # keyDict[keys[-1]] = value

            properties[keypath] = value

    return properties

if __name__ == '__main__':
    # Simple command-level driver for testing Java property file parsing.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
       '--file',
       help='Java property file',
       required=True
    )

    options = parser.parse_args()

    properties = load_property_file(file=options.file)
    for key, value in properties.items():
        print("%s: %s" % (key, value))
