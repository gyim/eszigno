#!/usr/bin/env python3
"""eszigno.py: Uncompress .es3 files"""

import argparse
import binascii
import io
import os
import sys
import zipfile

from xml.dom import minidom

ES = 'https://www.microsec.hu/ds/e-szigno30#'
DS = 'http://www.w3.org/2000/09/xmldsig#'

def sub_node(dom, child):
    return dom.getElementsByTagNameNS(ES, child)[0]

def sub_data(dom, child):
    return sub_node(dom, child).childNodes[0].data

class Document:
    def __init__(self, dom):
        # Title
        self.title = sub_data(dom, 'Title')

        # Date
        self.date = sub_data(dom, 'CreationDate')

        # MIME type and file extension
        mime_node = sub_node(sub_node(dom, 'Format'), 'MIME-Type')
        self.mime = '{mime_type}/{mime_subtype}'.format(
            mime_type=mime_node.getAttribute('type'),
            mime_subtype=mime_node.getAttribute('subtype'),
        )
        self.extension = mime_node.getAttribute('extension')

        # File size
        size_node = sub_node(dom, 'SourceSize')
        self.size = '{size_value} {size_unit}'.format(
            size_value=size_node.getAttribute('sizeValue'),
            size_unit=size_node.getAttribute('sizeUnit'),
        )

        # Filename
        if self.title.endswith(f'.{self.extension}'):
            self.filename = self.title
        else:
            self.filename = f'{self.title}.{self.extension}'

        # Encapsulation algorithms
        profile = sub_node(dom, 'DocumentProfile')
        self.algorithms = [t.getAttribute('Algorithm') for t in profile.getElementsByTagNameNS(ES, 'Transform')]
        
        # Payload
        self.payload = None
        objref = profile.getAttribute('OBJREF')
        for obj in dom.getElementsByTagNameNS(DS, 'Object'):
            id = obj.getAttribute('id')
            if obj.getAttribute('Id') == objref:
                self.payload = obj.childNodes[0].data
        if self.payload is None:
            raise ValueError(f'Cannot find payload for object {objref}')

    def decode_payload(self):
        payload = self.payload
        for algo in reversed(self.algorithms):
            if algo == 'base64':
                payload = binascii.a2b_base64(payload.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', ''))
            elif algo == 'zip':
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    for i, filename in enumerate(z.namelist()):
                        assert i == 0, f'Too many files in compressed payload: {self.title}'
                        with z.open(filename) as f:
                            payload = f.read()
            else:
                raise NotImplementedError(f'Unsupported algorithm: {algo}')
        return payload

class Dossier:
    def __init__(self, dom):
        self.documents = [Document(d) for d in dom.getElementsByTagNameNS(ES, 'Document')]

    @staticmethod
    def load(filename):
        with open(filename) as f:
            dom = minidom.parse(f)
            return Dossier(dom)

def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_subparsers(title='Commands', dest='cmd')

    ls = s.add_parser('ls', help='List encapsulated files in e-szigno file')
    ls.add_argument('input_file')

    extract = s.add_parser('extract', help='Extract files')
    extract.add_argument('input_file')
    extract.add_argument('-o', '--output-directory', default='.', help='Output directory (default: .)')

    args = p.parse_args()
    if not args.cmd:
        p.print_usage()
        sys.exit(1)

    return args

def cmd_ls(input_file):
    dossier = Dossier.load(input_file)

    fmt = '{date:20s} | {size:10s} | {mime:20s} | {filename}'
    print(fmt.format(date='Date', size='Size', mime='MIME', filename='Filename'))
    print(fmt.format(date='----', size='----', mime='----', filename='--------'))

    for document in dossier.documents:
        print(fmt.format(date=document.date, size=document.size, mime=document.mime, filename=document.filename))

def cmd_extract(input_file, output_directory):
    dossier = Dossier.load(input_file)

    for document in dossier.documents:
        print(document.filename)
        payload = document.decode_payload()
        with open(os.path.join(output_directory, document.filename), 'wb') as f:
            f.write(payload)

def main():
    args = parse_args()
    if args.cmd == 'ls':
        cmd_ls(args.input_file)
    if args.cmd == 'extract':
        cmd_extract(args.input_file, args.output_directory)

if __name__ == '__main__':
    main()
