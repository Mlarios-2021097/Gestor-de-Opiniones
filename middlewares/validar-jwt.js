const { response, request } = require('express');
const jwt = require('jsonwebtoken');

const validarJWT = async( req = request, res = response, next ) => {

    // x-token headers
    const token = req.header('x-token');

    if( !token ){
        return res.status(401).json({
            ok: false,
            msg: 'No hay token en la petición'
        })
    }

    try {

        const { uid, name} = jwt.verify(
            token,
            process.env.SECRET_JWT_SED
        );
       
       req.uid = uid;
       req.name = name;
        
       next();
    } catch (error) {
        return res.status(401).json({
            ok: false,
            msg: 'Token no valido'
        })
    }

    // next();

}


module.exports = {
    validarJWT
}