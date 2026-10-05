"""An empty SQLAlchemy-style RETURNING result for statement-recording tests."""


class EmptyRows:
    def scalars(self):
        return self

    def all(self):
        return []
