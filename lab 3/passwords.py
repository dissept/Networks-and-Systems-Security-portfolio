print("Password Checker")
pw=input("Enter Your Password Here: ")

#checking if password is to short, or to long.
if len(pw)<=5 or len(pw)>=18:
    if len(pw)<=5:
        print ("To Short")
    else:
        print ("Too Long")

else:#password is correct length
    #checking if a uppercase AND a lowwercase.
    if any(x.isupper() for x in pw) and any(x.islower() for x in pw):
        print ("Thats an excelent password")
    else:
        print ("Medium Password")