from typing import Any, Dict, List
from dependency_injector import containers, providers

from .pipeline.registry import get_class


class PipelineContainer(containers.DeclarativeContainer):
    """
    Wires components from config using automatic dependency injection.

    Components declare their dependencies via INJECT class attribute:
        INJECT = ["dialect"]  # Inject SQL dialect string
    """

    loader            = providers.Provider()
    normalizers_chain = providers.List()
    analyzers_chain   = providers.List()

    def wire_from_config(self, cfg: Dict[str, Any]) -> None:
        dialect = (cfg.get("dialect") or "sqlite").strip().lower()

        def build_provider(ComponentCls: type, params: Dict[str, Any]):
            """Build a provider with automatic dependency injection based on INJECT attribute."""
            inject_list = getattr(ComponentCls, 'INJECT', [])
            kwargs = dict(params)

            for inject_item in inject_list:
                if inject_item == "dialect":
                    kwargs["dialect"] = dialect

            return providers.Singleton(ComponentCls, **kwargs)

        # ---------- Loader ----------
        lcfg    = cfg.get("load") or {}
        lname   = lcfg.get("name")
        lparams = lcfg.get("params") or {}
        if not lname:
            raise ValueError("config.load.name is required")
        LoaderCls = get_class("loader", lname)
        self.loader = build_provider(LoaderCls, lparams)

        # ---------- Normalizers chain ----------
        n_specs = cfg.get("normalize") or []
        n_provs: List[providers.Provider] = []
        for spec in n_specs:
            name = spec.get("name")
            if not name:
                raise ValueError("normalize item must have name")
            params = dict(spec.get("params") or {})
            NormalizerCls = get_class("normalizer", name)
            n_provs.append(build_provider(NormalizerCls, params))

        self.normalizers_chain = providers.List(*n_provs)

        # ---------- Analyzers chain ----------
        a_specs = cfg.get("analyze") or []
        a_provs: List[providers.Provider] = []
        for spec in a_specs:
            name = spec.get("name")
            if not name:
                raise ValueError("analyze item must have name")
            params = dict(spec.get("params") or {})
            AnalyzerCls = get_class("analyzer", name)
            a_provs.append(build_provider(AnalyzerCls, params))

        self.analyzers_chain = providers.List(*a_provs)
