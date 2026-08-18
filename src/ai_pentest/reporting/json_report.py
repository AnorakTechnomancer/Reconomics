from pathlib import Path

from pydantic import BaseModel


def render_json(result: BaseModel) -> str:
    return result.model_dump_json(indent=2)


def write_json(result: BaseModel, output_path: str) -> None:
    path = Path(output_path)

    path.write_text(
        render_json(result) + "\n",
        encoding="utf-8",
    )