from sqlalchemy.sql import text


class TOTPClient:
    def __init__(self, db_engine) -> None:
        self.db_engine = db_engine

    def unset_totp_seed(self, user: str):
        """
        remove existing totp seed for a user
        """
        with self.db_engine.connect() as conn:
            delete = text("DELETE FROM totp_seed WHERE username = :username")
            conn.execute(delete, username=user)

    def get_user_totp_seed(self, user: str) -> str:
        """
        get a user's totp seed
        """
        with self.db_engine.connect() as conn:
            select = text("SELECT seed FROM totp_seed WHERE username = :username")
            result = conn.execute(select, username=user).fetchall()
            if len(result) == 1:
                return result[0][0]
            else:
                return None
