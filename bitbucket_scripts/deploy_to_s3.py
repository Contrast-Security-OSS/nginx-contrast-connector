import sys
import os
import subprocess
import tempfile
import glob
import re
import shutil
from zipfile import ZipFile


def get_artifact_version():
    for file in glob.glob('*'):
        file_version = re.search('([0-9]+\.){2}[0-9]', file)
        if file_version is not None:
            return file_version.group(0)
    raise ValueError('Artifact must have version (cannot retrieve version from filename)')


def get_revision():
    date = subprocess.check_output(
        ['bash', '-c', 'TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d-%H%M HEAD'])
    rev = subprocess.check_output(['bash', '-c', 'git rev-parse --short HEAD'])

    if isinstance(date, bytes):
        date = date.decode('utf-8').strip()
    if isinstance(rev, bytes):
        rev = rev.decode('utf-8').strip()
    return '{}.{}'.format(date, rev)


def is_debug_package(pkg_name):
    return 'dbg' in pkg_name or 'debuginfo' in pkg_name


def setup_directory(root_dir, deploy_file_name):
    deploy_path = os.path.join(root_dir, deploy_file_name)
    os.mkdir(deploy_path)
    deployment_files_path = os.path.join(deploy_path, 'deployment')
    os.mkdir(deployment_files_path)
    return deploy_path


def move_packages(dest_dir, deploy_version):
    if not os.path.exists(dest_dir):
        raise ValueError('Destination directory must exists before moving packages')

    archive_name = 'contrast-webserver-agent-{}'.format(deploy_version)
    zip_name = '{}.zip'.format(archive_name)

    zip_path = os.path.join(dest_dir, zip_name)
    with ZipFile(zip_path, 'w') as packages_zip:
        for file in glob.glob('*'):
            if is_debug_package(file):
                continue
            packages_zip.write(file)


def _move_verify_script(dest_dir):
    verify_script_path = os.path.join(os.getcwd(), '../code-deploy', 'verify.sh')

    if not os.path.exists(verify_script_path):
        raise ValueError('Cannot find verify.sh at {}'.format(verify_script_path))

    dest_path = os.path.join(dest_dir, 'deployment', 'verify.sh')

    shutil.copy(verify_script_path, dest_path)


def _move_start_script(dest_dir, deploy_version):
    start_script_path = os.path.join(os.getcwd(), '../code-deploy', 'start.sh')

    if not os.path.exists(start_script_path):
        raise ValueError('Cannot find start.sh at {}'.format(start_script_path))
    dest_path = os.path.join(dest_dir, 'deployment', 'start.sh')

    subprocess.call(['bash', '-c', 'cat {} | sed "s/WEBSERVER_BASE_VERSION/{}/g" > {}'.format(
        start_script_path,
        deploy_version,
        dest_path
    )])


def _move_appspec(dest_dir, deploy_version):
    archive_name = 'contrast-webserver-agent-{}'.format(deploy_version)
    zip_name = '{}.zip'.format(archive_name)

    app_spec_path = os.path.join(os.getcwd(), '../code-deploy', 'appspec.yml')
    if not os.path.exists(app_spec_path):
        raise ValueError('Cannot find appspec.yml at {}'.format(app_spec_path))

    dest_path = os.path.join(dest_dir, 'appspec.yml')

    subprocess.call(['bash', '-c', 'cat {} | sed "s/WEBSERVER_SOURCE/{}/g" > {}'.format(
        app_spec_path,
        zip_name,
        dest_path
    )])


def move_code_deploy_scripts(dest_dir, deploy_version):
    _move_verify_script(dest_dir)
    _move_start_script(dest_dir, deploy_version)
    _move_appspec(dest_dir, deploy_version)


def package_bundle(file_name):
    with ZipFile(file_name, 'w') as bundle_zip:
        for file in glob.glob('*'):
            if file == file_name:
                continue
            file_path = os.path.join(os.getcwd(), file)
            if os.path.isdir(file_path):
                bundle_zip.write(file)
                for sub_file in glob.glob(file_path + '/*'):
                    bundle_zip.write(
                        os.path.join(file, os.path.basename(sub_file))
                    )
            else:
                bundle_zip.write(file)


def update_file(file_name, content):
    with open(file_name, 'w+') as version_file:
        version_file.write(content)


def deploy_to_s3(revision, deploy_zip_file_name):
    base_path = os.path.join('s3://', 'contrast-internal-artifacts')
    deploy_types = {
        'nginx': os.path.join(base_path, 'webserver-agent-nginx')
    }

    base_path = deploy_types.get('nginx', base_path)

    deployed_version_path = os.path.join(base_path, 'version.txt')

    revision_path = os.path.join(base_path, revision)
    deployed_latest_path = os.path.join(revision_path, 'latest.txt')
    deployed_zip_file_path = os.path.join(revision_path, deploy_zip_file_name)

    subprocess.check_call(['bash', '-c', 'aws s3 cp version.txt {}'.format(deployed_version_path)])
    subprocess.check_call(['bash', '-c', 'aws s3 cp latest.txt {}'.format(deployed_latest_path)])
    subprocess.check_call(['bash', '-c', 'aws s3 cp {} {}'.format(
        deploy_zip_file_name,
        deployed_zip_file_path
    )])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise ValueError('Must have pkg directory and deploy type as arguments')

    pkg_dir = str(sys.argv[1])

    pkg_dir = os.path.join(os.getcwd(), pkg_dir)
    if not os.path.exists(pkg_dir):
        raise ValueError('Package dir must exists')

    print(pkg_dir)
    os.chdir(pkg_dir)

    deploy_version = get_artifact_version()

    revision = get_revision()

    deploy_file_name = 'webserver-agent-bundle-{}'.format(revision)
    deploy_zip_file_name = deploy_file_name + '.zip'

    with tempfile.TemporaryDirectory() as tmpdirname:
        deploy_path = setup_directory(tmpdirname, deploy_file_name)
        move_packages(deploy_path, deploy_version)
        move_code_deploy_scripts(deploy_path, deploy_version)

        os.chdir(deploy_path)
        package_bundle(deploy_zip_file_name)

        print('Deploying {} ({})'.format(deploy_file_name, deploy_version))
        update_file('version.txt', revision)
        update_file('latest.txt', deploy_zip_file_name)

        deploy_to_s3(revision, deploy_zip_file_name)
