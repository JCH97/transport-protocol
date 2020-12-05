# Trapy - José Carlos Hernández Piñera C311

Con el proyecto en cuestión se propone crear un protocolo de capa de transporte. Se intentó que el funcionamiento del mismo fuera lo más parecido posible al protocolo TCP, por lo que se siguieron las ideas de este durante el desarrollo.

Los paquetes que se envían tienen un tamaño de 512 bytes, incluidas ahí las cabeceras ip(12 bytes) y tcp(20 bytes); la implementación de dicho paquete se encuentra recogida en la clase _Packet_ dentro del módulo _packet.py_ que se encuentra dentro de _trapy_. La implementeación que se brinda de _send_ y _recv_ pretende garantizar la mayor confibilidad y asegurar que lleguen todos los paquetes; se asegura el orden de los mismos en todo momento. 

Se permite la comunicación bidireccional entre _cliente_ y _servidor_; pero cuando se simula esto en un ambiente con pérdida de paquetes es posible que no se pueda desarrollar correctamente la misma debido a la posible pérdida de los paquetes _ack_ en la transmisión; con pérdida de paquetes y comunicación en un solo sentido si se garantiza la correctitud de la implementación. 

El párrafo anterior expone el principal error del proyecto, el cual tal vez por una cuestión de tiempo no se pudo corregir a fondo.

Es posible hacer logs de todas las operaciones que va realizando el proyecto; para ello en las llamadas a _recv_ y _dial_ pasar **True** como segundo parámetro; obviamente esto es opcional.

Cualquier pregunta sobre el proyecto, sin problemas contactarme.


Para ejecutar el proyecto chequear el método main.
