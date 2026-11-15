"""SOC Alert Triage : appelle le workflow ``soc-alert-triage`` côté Mistral."""

from fastapi import params

segment = "soc"

# Module de démo served without a caller, comme ``internal``.
dependencies: tuple[params.Depends, ...] = ()
