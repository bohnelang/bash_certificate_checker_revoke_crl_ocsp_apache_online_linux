# Skript for checking if a ssl certicate is revoked

The script can check if a ssl certifcate is revoced and checks for valid days. 
 
The script first gets the chain certificate and looks for the Certificate Revocation List (CRL). After downloading this it checks if the serial no of the certificate is in this list. 
Checking the CRL list is the upto-date method. 
If this fails the script tries to fetch the outdated way by using Online Certificate Status Protocol (OCSP).

The script returns 'exit 0' for is ok and 'exit 1' for fail. 

You can us this in you own script like this:

```
./check_revoke.sh www.umm.uni-heidelberg.de
R=$?
if test $R -eq 0 
then
  <renwe your certificate by ACME>
fi
```


## check_revoke.sh
```
#!/bin/bash

#
# Online Certification Checker
#
# Andreas Bohne-Lang (2026)
#


args=("$@")

if test $# -gt 0
then
        H=${args[0]}
else
        H="www.umm.uni-heidelberg.de"
fi

#echo ">$H"

function check_enddate_valid()
{
        local ED=$(echo | openssl s_client -connect "$H:443" -servername $H 2>/dev/null | openssl x509 -noout -enddate | sed s/^notAfter=//g)


        local start=$(date --date="$ED" +"%Y-%m-%d")
        local ende=$(date  +"%Y-%m-%d")

        local s2=$(date -d "$start" +%s)
        local s1=$(date -d "$end" +%s)
        local d=$(( (s2 - s1) / 86400 ))

        echo "$d"
}


function check_OCSP()
{
        # Credits: https://gist.github.com/vanbroup/ca7d52a1a6006b5ba03b43d891384ed1 vanbroup/ocsp-request-script.sh

        local FN=/tmp

        # Getting certificate from TLS handshake
        openssl s_client -connect "$H:443" -servername "$H" < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' > ${FM}/certificate.pem

        # Getting intermediates from TLS handshake
        openssl s_client -showcerts -connect "$H:443" < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' | sed -n '/^-----END CERTIFICATE-----/,$ p' | sed 1d > ${FM}/chain.pem

        # Finding OCSP server in certificate
        local ocsp=$(openssl x509 -noout -ocsp_uri -in ${FM}/certificate.pem)

        ## Remove protocol part of url  ##
        local host=$ocsp
        host="${host#http://}"
        host="${host#https://}"

        ## Remove rest of urls ##
        host=${host%%/*}

        if ! test "$host" = ""
        then
                RET="ocsp revoked"
                while read line
                do
                        if ! test "$(echo $line |  grep certificate.pem | grep good)" = ""
                        then
                                RET="valid"
                        fi
                done < <(openssl ocsp -noverify -no_nonce -respout ${FM}/ocsp.resp -reqout ${FM}/ocsp.req -issuer ${FM}/chain.pem -cert ${FM}/certificate.pem -text -url $ocsp -header 'Host'=$host)
                # Making OCSP request to $ocsp ($host) saving a copy of the request to ocsp.req and the response to ocsp.resp
        else
                RET="error"
        fi

        rm -f $FN/certificate.pem
        rm -f $FN/chain.pem
        rm -f $FN/ocsp.req
        rm -f $FN/ocsp.resp

        echo $RET
}




function check_serial_is_revoked()
{

# X509v3 CRL Distribution Points:
#                Full Name:
#                  URI:http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl


        CRL_URL=""

        while read line
        do
                if(  ! test "$(echo $line | grep 'CRL Distribution')" = ""  )
                then
                        read line2
                        read line3
                        CRL_URL=$(echo "$line3"| sed s/^URI://g | awk {'print $1'})
                        break
                fi
        done < <(echo | openssl s_client -showcerts -servername $H -connect "$H:443" 2>/dev/null | openssl x509 -inform pem -noout -text)


        if ! test "$CRL_URL" = ""
        then
                local RET="valid"
                local S=$(echo | openssl s_client -connect "$H:443" -showcerts </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'| openssl x509 -noout -serial | sed s/^serial=//g)

                Z=$(wget -q -O - $CRL_URL | openssl crl -inform DER -text -noout | grep "Serial Number:" )

                #Z=$(cat ./tmpx)

                if ! test "$(echo $Z | grep $S)" = ""
                then
                        RET="crl revoked"
                fi
        else
                RET="error"
        fi


        echo $RET
}


#check certificate revocation list
Y=$(check_serial_is_revoked)

# Fallbeack to Online Certificate Status Protocol (OCSP) if certificate revocation list (CRL) fails
if test "$Y" = "error"
then
        Y=$(check_OCSP)
fi


X=$(check_enddate_valid)


echo "($X)($Y)"

if test $X -le 45 || ! test  "$Y" = "valid"
then
        exit 1
else
        exit 0

```
