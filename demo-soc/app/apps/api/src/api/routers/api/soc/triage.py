"""Endpoint de triage d'alerte : délègue au workflow ``soc-alert-triage``."""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from utils.mistral import mistral_client

router = APIRouter()

WORKFLOW_IDENTIFIER = "soc-alert-triage"


class TriageRequest(BaseModel):
    alerte: str = Field(description="Alerte de sécurité en JSON (string)")


class TriageResponse(BaseModel):
    execution_id: str
    rapport: str


@router.post(
    "",
    operation_id="soc_triage",
    summary="Trie une alerte via le workflow soc-alert-triage et renvoie le rapport markdown",
)
async def triage(req: TriageRequest) -> TriageResponse:
    client = mistral_client()
    execution = client.workflows.execute_workflow(
        workflow_identifier=WORKFLOW_IDENTIFIER,
        input={"alerte": req.alerte},
        wait_for_result=True,
    )
    data = execution.model_dump()
    resultat = data.get("result") or {}
    rapport = resultat.get("result") if isinstance(resultat, dict) else str(resultat)
    return TriageResponse(execution_id=data.get("execution_id", ""), rapport=str(rapport))
