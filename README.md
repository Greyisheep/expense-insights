├── services/
│   ├── efms-service/                # Expense & File Management (Go)
│   │   ├── cmd/                      # entrypoint (main.go)
│   │   ├── configs/                  # service‑specific config
│   │   ├── internal/
│   │   │   ├── domain/               # entities & value objects
│   │   │   ├── repository/           # data access layer
│   │   │   ├── service/              # use‑case logic
│   │   │   ├── handler/              # HTTP/gRPC handlers
│   │   │   └── middleware/           # cross‑cutting concerns
│   │   ├── scripts/                  # migrations, helpers
│   │   ├── Dockerfile
│   │   ├── Makefile
│   │   └── go.mod
│   ├── auth-service/                # Authentication & JWT (Go)
│   │   ├── cmd/
│   │   ├── configs/
│   │   ├── internal/
│   │   ├── scripts/
│   │   ├── Dockerfile
│   │   ├── Makefile
│   │   └── go.mod
│   └── insights-service/            # Insights & ETL (Python)
│       ├── app/
│       │   ├── api/                  # FastAPI routers
│       │   ├── core/                 # startup & settings
│       │   ├── models/               # Pydantic schemas
│       │   ├── services/             # business logic
│       │   ├── repositories/         # DB access
│       │   └── deps.py               # DI definitions
│       ├── tests/                    # unit & integration tests
│       ├── Dockerfile
│       ├── pyproject.toml
│       └── Makefile
├── shared/                          # common libraries (auth, logging, metrics)
│   └── …
├── configs/                         # global config templates
├── infra/                           # IaC: k8s manifests, Terraform
│   ├── k8s/
│   └── terraform/
├── scripts/                         # repo‑wide tooling
├── tests/                           # BDD tests (Gherkin + step defs)
│   ├── features/                    # .feature files per domain
│   │   ├── expense-management.feature
│   │   ├── file-processing.feature
│   │   ├── auth.feature
│   │   └── insights.feature
│   ├── step_definitions/            # Go & Python bindings for steps
│   └── support/                     # fixtures, hooks, test utilities
├── docker-compose.yml               # local orchestration
├── .golangci.yml                    # Go linter config
├── pytest.ini                       # Python test config
├── Makefile                         # high‑level commands (build, test, lint)
└── README.md                        # project overview & setup
