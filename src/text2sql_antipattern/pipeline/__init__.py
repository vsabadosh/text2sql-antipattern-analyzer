
def import_builtin_plugins() -> None:
    # LOADERS
    import text2sql_antipattern.loaders.jsonl_loader
    import text2sql_antipattern.loaders.json_loader
    import text2sql_antipattern.loaders.csv_loader

    # NORMALIZERS
    import text2sql_antipattern.normalizers.alias_mapper
    import text2sql_antipattern.normalizers.id_assign

    # ANALYZERS
    import text2sql_antipattern.analyzers.query_antipattern.query_antipattern_analyzer
