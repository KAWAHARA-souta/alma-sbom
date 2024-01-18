#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-

import argparse
import dataclasses
import logging
import os
import sys
from collections import defaultdict
from typing import Dict, List, Literal, Optional, Tuple

import requests
from immudb_wrapper import ImmudbWrapper

ALBS_URL = 'https://build.almalinux.org'

@dataclasses.dataclass
class PackageNevra:
    name: str = None
    epoch: str = None
    version: str = None
    release: str = None
    arch: str = None

    def __repr__(self):
        if self.epoch is not None:
            return (
                f'{self.epoch}:{self.name}-'
                f'{self.version}-{self.release}.{self.arch}'
            )
        return f'{self.name}-{self.version}-' f'{self.release}.{self.arch}'



def _extract_immudb_info_about_package(
    immudb_hash: str,
    immudb_wrapper: ImmudbWrapper,
) -> Dict:
    response = immudb_wrapper.authenticate(immudb_hash)
    result = response.get('value', {})
    result['timestamp'] = response.get('timestamp')
    return result

def _get_specific_info_about_package(
    immudb_info_about_package: Dict,
) -> Tuple[Optional[str], PackageNevra]:
    immudb_metadata = immudb_info_about_package['Metadata']
    # We have `sbom_api_ver` in git records and `sbom_api`
    # in RPM package records. The latter parameter is the bug,
    # but we should handle it anyway
    # since a lot of packages already have it.
    api_ver = immudb_metadata.get('sbom_api_ver')
    if not api_ver:
        api_ver = immudb_metadata.get('sbom_api')
    if not api_ver:
        raise ValueError(
            'Immudb metadata is malformed, API version cannot be detected'
        )
    if api_ver == '0.1':
        package_name = immudb_info_about_package['Name']
        package_nevra = split_name_of_package_by_nevra(package_name)
        source_rpm = None
    else:
        package_nevra = PackageNevra(
            name=immudb_metadata['name'],
            epoch=immudb_metadata['epoch'],
            version=immudb_metadata['version'],
            release=immudb_metadata['release'],
            arch=immudb_metadata['arch'],
        )
        source_rpm = immudb_metadata['sourcerpm']
    return source_rpm, package_nevra



def get_info_about_package(
    immudb_hash: str,
    albs_url: str,
    immudb_wrapper: ImmudbWrapper,
):
    result = {}
    immudb_info_about_package = _extract_immudb_info_about_package(
        immudb_hash=immudb_hash,
        immudb_wrapper=immudb_wrapper,
    )
    source_rpm, package_nevra = _get_specific_info_about_package(
        immudb_info_about_package=immudb_info_about_package,
    )
    immudb_metadata = immudb_info_about_package['Metadata']
    result['version'] = 1
    if 'unsigned_hash' in immudb_metadata:
        result['version'] += 1
    result['component'] = {
        'name': package_nevra.name,
        'version': (
            f'{package_nevra.epoch if package_nevra.epoch else ""}'
            f'{":" if package_nevra.epoch else ""}'
            f'{package_nevra.version}-{package_nevra.release}'
        ),
        'hashes': [
            {
                'alg': 'SHA-256',
                'content': immudb_hash,
            }
        ],
        #'cpe': _generate_cpe(package_nevra=package_nevra),
        #'purl': _generate_purl(
            #package_nevra=package_nevra,
            #source_rpm=source_rpm,
        #),
        'properties': [
            {
                'name': 'almalinux:package:epoch',
                'value': package_nevra.epoch,
            },
            {
                'name': 'almalinux:package:version',
                'value': package_nevra.version,
            },
            {
                'name': 'almalinux:package:release',
                'value': package_nevra.release,
            },
            {
                'name': 'almalinux:package:arch',
                'value': package_nevra.arch,
            },
            {
                'name': 'almalinux:package:sourcerpm',
                'value': source_rpm,
            },
            {
                'name': 'almalinux:package:buildhost',
                'value': immudb_metadata['build_host'],
            },
            {
                'name': 'almalinux:package:timestamp',
                'value': immudb_info_about_package['timestamp'],
            },
            {
                'name': 'almalinux:albs:build:targetArch',
                'value': immudb_metadata['build_arch'],
            },
            {
                'name': 'almalinux:albs:build:packageType',
                'value': 'rpm',
            },
            {
                'name': 'almalinux:sbom:immudbHash',
                'value': immudb_hash,
            },
            {
                'name': 'almalinux:albs:build:ID',
                'value': immudb_metadata['build_id'],
            },
            {
                'name': 'almalinux:albs:build:URL',
                'value': f'{albs_url}/build/{immudb_metadata["build_id"]}',
            },
            {
                'name': 'almalinux:albs:build:author',
                'value': immudb_metadata['built_by'],
            },
        ],
    }

    #add_package_source_info(
        #immudb_metadata=immudb_metadata,
        #component=result['component'],
    #)
    return result



def cli_main():
    immudb_wrapper = ImmudbWrapper(
        username=ImmudbWrapper.read_only_username(),
        password=ImmudbWrapper.read_only_password(),
        database=ImmudbWrapper.almalinux_database_name(),
        immudb_address=ImmudbWrapper.almalinux_database_address(),
    )
    albs_url = ALBS_URL


    immudb_info_about_package = _extract_immudb_info_about_package(
        immudb_hash="e86c3d10f3185114d4021a6ed512d4a0d9e0ac2a62766e593d862c33fe9ac09b",
        immudb_wrapper=immudb_wrapper,
    )
    source_rpm, package_nevra = _get_specific_info_about_package(
        immudb_info_about_package=immudb_info_about_package,
    )

    print(immudb_info_about_package['Metadata'])



if __name__ == '__main__':
    cli_main()






    #print("### kernel-5.14.0-162.12.1.el9_1.x86_64 ###")
    #kernel_targetver_sbom = get_info_about_package(
        #"449253dc6197374682b579374b9ff3afda6d3fda38107a6187c00564cae20354", #args.rpm_package_hash,
        #albs_url=albs_url,
        #immudb_wrapper=immudb_wrapper,
    #)
    #print(kernel_targetver_sbom['version'])
    #print(kernel_targetver_sbom['component'])
    #print()
#
    #print("### osbuild-93-1.el9.alma.1 ###")
    #osbuild_targetver_sbom = get_info_about_package(
        #"f3b9a5f0b02b91bb23d5c54136aec62199e0d93d12d3529f42d475e3e94f29c4", #args.rpm_package_hash,
        #albs_url=albs_url,
        #immudb_wrapper=immudb_wrapper,
    #)
    #print(osbuild_targetver_sbom['version'])
    #print(osbuild_targetver_sbom['component'])
#
