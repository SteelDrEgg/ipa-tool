import os

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
import pathlib
import json

from .create_infos import ipaInfos
from .get_icon import ipng2png

app = typer.Typer()


@app.command()
def get_info(ipa_path: str = typer.Argument(..., help="Aboslute path to .ipa file"),
            output_path: str = typer.Option('', '-o', help='The path to directory where you want the output files be'),
            multi_icon: bool = typer.Option(False, '-mi', help='Get multiple icon if possible')):
    ipa_path = str(pathlib.Path(ipa_path).absolute())

    # Creating progress bar
    progress = Progress(SpinnerColumn(), TextColumn('{task.description}'))
    with progress:
        # Creating progress bar task
        general_task = progress.add_task("[green]Loading ipa", total=None)
        ipa_info = ipaInfos(ipa_path, get_multi_icon=multi_icon)

    # Truning md5 to str in order to print or write
    ipa_info.md5 = str(ipa_info.md5, encoding='ascii')
    # If have output path write to json, or print it
    if len(output_path) > 0:
        output_path = str(pathlib.Path(output_path).absolute())
        for icon in ipa_info.icon.keys():
            open(output_path + '/' + icon, 'wb').write(ipa_info.icon[icon])
            ipa_info.icon[icon] = output_path + '/' + icon
        json.dump(ipa_info.__dict__,
                  open(output_path + '/ipa_infos.json', 'w'),
                  indent=2,
                  sort_keys=True)

    else:
        for icon in ipa_info.icon.keys():
            ipa_info.icon[icon] = str(ipa_info.icon[icon])
        print(
            json.dumps(ipa_info.__dict__,
                       indent=2,
                       sort_keys=True)
        )

@app.command()
def cgbi2png(ipng_path: str = typer.Argument(..., help="Aboslute path to apple CgBI file"),
             output_path: str = typer.Argument(..., help='The path to directory where you want the output files be')):
    ipng_path = str(pathlib.Path(ipng_path).absolute())
    output_path = str(pathlib.Path(output_path).absolute())

    png=ipng2png(open(ipng_path,'rb').read())
    if '.png' in output_path:
        open(output_path,'wb').write(png)
    else:
        open(output_path+os.sep+ipng_path.split(os.sep)[-1],'wb').write(png)