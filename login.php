<?php
// Aqui incluyo el archivo de las credenciales para la conexion a la base de datos.
require_once "C:\config.php";

// Conexion a la base de datos a traves del archivo incluido mediante la funcion require_once 
$conexion = mysqli_connect($DB_HOST, $DB_USER, $DB_PASSWORD, $DB_NAME);

// Aqui se verifica si se ha realizado la conexión
if (!$conexion) {
  die("Error de conexión: " . mysqli_connect_error());
}

// Aqui se obtienen los datos enviados desde el formulario HTML
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $username = $_POST["username"];
  $password = $_POST["password"];

  // Aqui se realiza la Validación de datos
  if (empty($username) || empty($password)) {
    $response = array("success" => false, "error" => "Todos los campos son obligatorios.");
    header('Content-Type: application/json');
    echo json_encode($response);
    mysqli_close($conexion);
    exit;
  }

  // Aqui se realiza el saneamiento de datos
  $username = htmlspecialchars($username);
  $password = htmlspecialchars($password);

  // Aqui se prepara la sentencia SQL utilizando un marcador de posición (?)
  $consulta = "SELECT password FROM usuarios WHERE username = ?";
  
  // Aqui se crea la sentencia preparada
  $stmt = mysqli_prepare($conexion, $consulta);

  if ($stmt) {
    // Aqui se vincula el parámetro con el valor de la variable $username
    mysqli_stmt_bind_param($stmt, "s", $username);
    
    // Aqui se ejecuta la consulta
    mysqli_stmt_execute($stmt);

    // Aqui se obtiene el resultado de la consulta
    $resultado = mysqli_stmt_get_result($stmt);

    if (!$resultado) {
      // Si hay un error en la consulta, muestra el mensaje de error y detiene la ejecucion
      $response = array("success" => false, "error" => mysqli_error($conexion));
      header('Content-Type: application/json');
      echo json_encode($response);
      mysqli_stmt_close($stmt);
      mysqli_close($conexion);
      exit;
    }

    if (mysqli_num_rows($resultado) > 0) {
      // Si la consulta devuelve resultados, obtiene el hash almacenado en la base de datos
      $fila = mysqli_fetch_assoc($resultado);
      $hashContraseñaAlmacenada = $fila["password"];

      // Aqui se verifica si la contraseña proporcionada coincide con el hash almacenado
      if (password_verify($password, $hashContraseñaAlmacenada)) {
        // Si la contraseña coincide, las credenciales son válidas
        $response = array("success" => true);
      } else {
        // Si la contraseña no coincide, las credenciales son incorrectas
        $response = array("success" => false);
      }

      header('Content-Type: application/json');
      echo json_encode($response);
      
    } else {
      // Si no se encontró el usuario, las credenciales son incorrectas
      $response = array("success" => false);
      header('Content-Type: application/json');
      echo json_encode($response);
    }

    // Aqui se cierra el resultado de la consulta
    mysqli_free_result($resultado);
    
    // Aqui se cierra la sentencia preparada
    mysqli_stmt_close($stmt);
  } else {
    // Si hay un error al preparar la consulta, muestra el mensaje de error y detiene la ejecucion
    $response = array("success" => false, "error" => mysqli_error($conexion));
    header('Content-Type: application/json');
    echo json_encode($response);
    mysqli_close($conexion);
    exit;
  }
}

// Cerrar la conexión a la base de datos
mysqli_close($conexion);
?>
