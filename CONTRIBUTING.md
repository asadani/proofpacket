# Contributing

Read [PRODUCT.md](PRODUCT.md) and [the design plan](docs/PLAN.md) before changing behavior.

Use Python 3.11 or newer. Runtime code uses the standard library. Work in a branch,
keep changes focused, and add behavior tests for changed rules and failure cases.

```sh
python -m unittest discover -s tests -v
```

Update examples and README commands when interfaces change. Keep inferred findings
separate from observed facts. Do not include real private organization documents,
credentials, or participant data in fixtures. These tools are advisory unless a
particular check is explicitly described as deterministic.
