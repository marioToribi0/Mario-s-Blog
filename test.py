# # def render_template(**kwargs):
# #     for key in kwargs.keys():
# #         print(f"{key}: {kwargs[key]}")

# # render_template(hello="sii", date="15", ou="k")

# ##Only admin
# def only_admin(funct):

#     def wrapper(**kwargs):
#         kwargs["logged_in"] = True
#         funct(**kwargs)
    
#     return wrapper

# @only_admin
# def render_template(**kwargs):
#     for key in kwargs.keys():
#         print(f"{key}: {kwargs[key]}")


# render_template(hello="sii", date="15", ou="k")

import hashlib

string = "MyEmailAddress@example.com"

#data = hashlib.md5(string)
data_2 = (string)
data_2 =hashlib.md5(bytes(data_2, 'utf-8'))

#print(data.hexdigest())
print(data_2.hexdigest())