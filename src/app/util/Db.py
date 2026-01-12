from sqlite3 import connect, Connection

class Db:
    def __init__(self, filePath:str):
        self._filePath = filePath
    def getCon(self) -> Connection:
        return connect(self._filePath)
    def execAndCommit(self, sql:str, params:tuple=()) -> None:
        con = self.getCon()
        con.execute(sql, params)
        con.commit()
        con.close()
    def fetchOne(self, sql:str, params:tuple=()) -> tuple:
        con = self.getCon()
        con.execute(sql, params)
        r = con.cursor().fetchone()
        con.close()
        return r
    def fetchAll(self, sql:str, params:tuple=()) -> tuple:
        con = self.getCon()
        con.execute(sql, params)
        r = con.cursor().fetchall()
        con.close()
        return r