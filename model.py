import fdb

class Livros:
    def __init__(self, id_livros, titulo, autor, ano_publicacao):
        self.id_livros = id_livros
        self.titulo = titulo
        self.autor = autor
        self.ano_publicacao = ano_publicacao

class Usuarios:
    def __init__(self, id_usuarios, nome, email, senha):
        self.id_usuarios = id_usuarios
        self.nome = nome
        self.email = email
        self.senha = senha
