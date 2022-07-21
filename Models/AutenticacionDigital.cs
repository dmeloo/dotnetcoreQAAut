namespace Web.Models
{
    /// <summary>
    /// Clase que representa los claims
    /// </summary>
    public class AutenticacionDigital
    {
        public string sub { get; set; }
        public string auth_time { get; set; }
        public string idp { get; set; }
        public string acr { get; set; }
        public string name { get; set; }
        public string s_hash { get; set; }
        public string Identificacion { get; set; }
        public string TipoIdentificacion { get; set; }
        public string LOA { get; set; }
        public string PrimerNombre { get; set; }
        public string SegundoNombre { get; set; }
        public string PrimerApellido { get; set; }
        public string SegundoApellido { get; set; }
        public string nickname { get; set; }
        public string Telefono { get; set; }
        public string Direccion { get; set; }
        public string DireccionJSON { get; set; }
        public string preferred_username { get; set; }
        public string email { get; set; }
        public string email_verified { get; set; }
        public string amr { get; set; }
    }
}
