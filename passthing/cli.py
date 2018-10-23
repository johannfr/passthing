import click
import time
import subprocess
from sys import exit

from passthing import PassDatabase
from passthing.PassDatabase import EntryNotFound, InvalidPassword, NotConfigured

# Utility functions
def echo_error(message):
    click.echo(click.style('error: ', fg='red', bold=True) + message, err=True)

def copy_clipboard(text):
    xclip_process = subprocess.Popen(['xclip', '-i'], stdin=subprocess.PIPE)
    xclip_process.communicate(text)
    xclip_process = subprocess.Popen(['xclip', '-i', '-selection', 'clipboard'], stdin=subprocess.PIPE)
    xclip_process.communicate(text)

def output_password(password, clipboard=True):
    copy_clipboard(password)
    with click.progressbar(
        range(10),
        show_percent=False,
        bar_template='[%(bar)s] %(label)s',
        label='Copied to clipboard'
    ) as timeout:
        for second in timeout:
            time.sleep(1)
    copy_clipboard(b'')

def enforce_configured(is_configured):
    if not is_configured:
        raise NotConfigured()


# Command handlers
def entry_names_completion(ctx, args, incomplete):
    database_name = None
    for k,v in enumerate(args):
        if v == '--database':
            database_name = args[k+1]
            break
    if not database_name:
        import os
        try:
            database_name = os.environ['PASSTHING_DB']
        except KeyError:
            echo_error('No database configured')
            exit(1)
    pass_database = PassDatabase(database_name)
    return [k for k in pass_database.get_entry_names() if incomplete in k]

@click.group()
@click.option(
    '--database',
    required=True,
    envvar='PASSTHING_DB',
)
@click.pass_context
def cli(ctx, database):
    ctx.obj = PassDatabase(database)

@cli.command()
@click.pass_context
def ls(ctx):
    enforce_configured(ctx.obj.is_configured())
    for entry in ctx.obj.get_entry_names():
        click.echo(entry)

@cli.command()
@click.argument('name', autocompletion=entry_names_completion)
@click.pass_context
def modify(ctx, name):
    enforce_configured(ctx.obj.is_configured())
    if name not in ctx.obj.get_entry_names():
        echo_error('No such entry')
        return
    current_username = ctx.obj.get_username(name)
    username = click.prompt(
        'Username',
        default=current_username
    )
    password = click.prompt(
        'Password (g = generate new)',
        hide_input=True,
        default='leave unchanged'
    )

    if username != current_username:
        ctx.obj.set_username(name, username)

    if password != 'leave unchanged':
        master_password = click.prompt(
        'Master password',
        hide_input=True,
        )
        if password == 'g':
            save_password = ctx.obj.generate_password()
        else:
            save_password = password

        try:
            ctx.obj.set_password(name, master_password, save_password)
        except InvalidPassword:
            echo_error('Invalid master-password')
            return
        if password == 'g':
            output_password(bytes(save_password, 'utf-8'))



@cli.command()
@click.option('--name', prompt=True)
@click.pass_context
def new(ctx, name):
    enforce_configured(ctx.obj.is_configured())

    if name in ctx.obj.get_entry_names():
        echo_error('Entry already exists')
        return

    username = click.prompt(
        'Username'
    )
    password = click.prompt(
        'Password (. for multiline)',
        hide_input=True,
        default='auto-generate'
    )
    if password == '.':
        password = click.edit()
        if password is None:
            raise click.Abort()
    master_password = click.prompt(
        'Master password',
        hide_input=True,
    )

    if password == 'auto-generate':
        save_password = ctx.obj.generate_password()
    else:
        save_password = password

    try:
        ctx.obj.set_entry(name, master_password, username, save_password)
    except InvalidPassword:
        echo_error('Invalid master-password')
        return

    if password == 'auto-generate':
        output_password(bytes(save_password, 'utf-8'))



@cli.command()
@click.argument('name', autocompletion=entry_names_completion)
@click.pass_context
def get(ctx, name):
    enforce_configured(ctx.obj.is_configured())

    master_password = click.prompt(
        'Master password',
        hide_input=True,
    )
    try:
        username, password = ctx.obj.get_entry(name, master_password)
        click.echo('Username: {}'.format(username))
        if password.decode('utf-8').count('\n') > 0:
            click.edit(password.decode('utf-8'))
        else:
            output_password(password)
    except InvalidPassword:
        echo_error('Invalid master-password')

@cli.command()
@click.argument('name', autocompletion=entry_names_completion)
@click.pass_context
def rm(ctx, name):
    enforce_configured(ctx.obj.is_configured())

    if name not in ctx.obj.get_entry_names():
        echo_error('No such entry')
        return

    ctx.obj.remove_entry(name)

@cli.command()
@click.pass_context
def init(ctx):
    if ctx.obj.is_configured():
        echo_error('Database already initialized')

    master_password = click.prompt(
        'Master password',
        hide_input=True,
        confirmation_prompt=True
    )
    ctx.obj.initialize(master_password)
