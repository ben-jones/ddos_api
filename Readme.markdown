<header><h1><center>GIRST DDOS API</center></h1>
<h4><center>Get It Right the Second Time</center></h4>
<h3><center>Coded by Ben Jones</center></h3></header>




#### Overview ####
* This API is designed to failover services in the case of a Distributed Denial of Service Attack.
* The code and more information can be found in the Git Hub repository for the project [here](https://github.com/benwritescode/first_spiral.git).

#### Usage ####
* The API is designed to be used to receive data on a single socket specified in the configuration and if more sockets are needed, the user will need to instantiate additional instances of the API
* The object that the service passes to the API must include a get_data(int id, string data) method to receive information from the web where id is a reference to the connection that sent the data.
* The object from the service must also implement the to_yaml method to convert itself into yaml 
* More information and the interface to the API can be found in the file "DDOS API Interface.pdf"
