/**
Copyright 2021 cryptoflop.org
Gestion des changements de mots de passe.
**/
randompwd(len) = {
  externstr(Str("base64 /dev/urandom | head -c ",len))[1];
}
dryrun=1;
sendmail(address,subject,message) = {
  cmd = strprintf("echo %d | mail -s '%s' %s",message,subject,address);
  if(dryrun,print(cmd),system(cmd));
}
chpasswd(user,pwd) = {
  cmd = strprintf("yes %s | passwd %s",pwd,user);
  if(dryrun,print(cmd),system(cmd));
}
template = {
  "Cher collaborateur, votre nouveau mot de passe est %s. "
  "Merci de votre comprehension, le service informatique.";
  }
change_password(user,modulus,e=7) = {
  iferr(
    pwd = randompwd(10);
    chpasswd(user, pwd);
    address = strprintf("%s@cryptoflop.org",user);
    mail = strprintf(template, pwd);
    m = fromdigits(Vec(Vecsmall(mail)),128);
    c = lift(Mod(m,modulus)^e);
    sendmail(address,"Nouveau mot de passe",c);
    print("[OK] changed password for user ",user);
  ,E,print("[ERROR] ",E));
}

\\=====================================
\\        Attaque de Coppersmith
\\=====================================

\\on connait ici une partie du clair. On a le schéma suivant :
\\onconnaitceciXXXXXXXetcela
\\=
\\onconnaitceci0000000etcela
\\ +           XXXXXXX000000
\\On veut donc trouver la solution du système suivant :
\\ (X + connu ) ^e = chiffre modulo n
\\ on va s'appuyer sur la fonction de PARIGP zncoppersmith
\\L'attaque de Coppersmith est efficace sur le petit exposant de déchiffrement.
\\Son principe d'attaque est basé sur le fait suivant :
\\si on fixe la borne supérieure des racines étudiées du polynome à n^(1/d-eps), pour eps petit,
\\ on peut trouver les racines du polynome inférieures à X.
\\ Il s'agit du théoreme de Coppersmith.
\\a noter, pour l'usage de zncoppersmith de PARI GP,
\\ qu'il est important de multiplier x par un coefficient en cas de décalage,
\\ ce qui est ici le cas

\\==============================

encode(m) = fromdigits(Vec(Vecsmall(m)),128);
decode(c) = {Strchr(digits(c,128));};

text = readvec("input.txt");
cach = text[2];
n = text[1][1];
e = text[1][2];
message = Strprintf(template,"          ");
limit = 128^10;
chiffr = encode(message);
print(chiffr);
dechiffr = zncoppersmith((chiffr + 128^56*x)^e - cach,n,limit);
print(Strprintf(template,decode(dechiffr[1])));
