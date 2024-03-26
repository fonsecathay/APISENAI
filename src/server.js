import fastify from "fastify";
import z from 'zod'
import pgk from 'bcryptjs'
import {prisma} from './lib/prisma.js'

const {compare, hash} = pgk

const app = fastify()

app.post('/users', async (request, reply) => {
    const registerBodySchema = z.object({
        name: z.string(),
        email: z.string(),
        password: z.string().min(6)
    })
    //Dados que precisam ser colocados no body
    const {name, email, password} = registerBodySchema.parse(request.body)

    //Criptografar senha
    const password_hash = await hash(password, 6)
     
    //verificar se o email já existe no banco de dados
    const userWithSameEmail = await prisma.users.findUnique({
        where:{
            email
        }
    })

    //se existir mostrar um erro
    if(userWithSameEmail){
        return reply.status(409).send({menssage:'E-mail já existe'})
    }
    
    //Criar cadastro de dados 
    await prisma.users.create({
        data:{
            name,
            email,
            password_hash
        }
    })
    return reply.status(201).send()
 })

app.listen({
    host:'0.0.0.0',
    port: 3333
}).then(() => {
    console.log('🚀Servidor rodando na porta 3333');
})